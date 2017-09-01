# -*- coding: utf-8 -*-
"""A gcdt-plugin to do lookups."""
from __future__ import unicode_literals, print_function
import sys
import json
from copy import deepcopy

from botocore.exceptions import ClientError
from gcdt import gcdt_signals
from gcdt.servicediscovery import get_ssl_certificate, get_outputs_for_stack
#    get_base_ami
from gcdt.gcdt_logging import getLogger
from gcdt.gcdt_awsclient import ClientError
from gcdt.utils import stack_exists, get_plugin_defaults
#from gcdt.kumo_core import stack_exists
from gcdt.utils import GracefulExit, dict_merge
from gcdt.gcdt_openapi import get_openapi_defaults, validate_tool_config, \
    incept_defaults_helper, validate_config_helper
from . import read_openapi


from .credstash_utils import get_secret, ItemNotFound

PY3 = sys.version_info[0] >= 3

if PY3:
    basestring = str

log = getLogger(__name__)

GCDT_TOOLS = ['kumo', 'tenkai', 'ramuda', 'yugen']


def _resolve_lookups(context, config, lookups):
    """
    Resolve all lookups in the config inplace
    note: this was implemented differently to return a resolved config before.
    """
    awsclient = context['_awsclient']
    # stackset contains stacks and certificates!!
    stackset = _identify_stacks_recurse(config, lookups)

    # cache outputs for stack (stackdata['stack'] = outputs)
    stackdata = {}

    for stack in stackset:
        # with the '.' you can distinguish between a stack and a certificate
        if '.' in stack and 'ssl' in lookups:
            stackdata.update({
                stack: {
                    'sslcert': get_ssl_certificate(awsclient, stack)
                }
            })
        elif 'stack' in lookups:
            try:
                stackdata.update({stack: get_outputs_for_stack(awsclient, stack)})
            except ClientError as e:
                # probably a greedy lookup
                pass

    # the gcdt-lookups plugin does "greedy" lookups
    for k in config.keys():
        try:
            if isinstance(config[k], basestring):
                # Don't think we have many of these??!
                config[k] = _resolve_single_value(awsclient, config[k],
                                                  stackdata, lookups)
            else:
                _resolve_lookups_recurse(
                    awsclient, config[k], stackdata, lookups, k == 'yugen')
        except GracefulExit:
            raise
        except Exception as e:
            if k in [t for t in GCDT_TOOLS if t != context['tool']]:
                # for "other" deployment phases & tools lookups can fail
                # ... which is quite normal!
                # only lookups for config['tool'] must not fail!
                pass
            else:
                log.debug(str(e), exc_info=True)  # this adds the traceback
                context['error'] = \
                    'lookup for \'%s\' failed: %s' % (k, json.dumps(config[k]))
                log.error(str(e))
                log.error(context['error'])


def _resolve_lookups_recurse(awsclient, config, stacks, lookups, is_yugen=False):
    # resolve inplace
    if isinstance(config, dict):
        for key, value in config.items():
            if isinstance(value, dict):
                _resolve_lookups_recurse(
                    awsclient, value, stacks, lookups, is_yugen)
            elif isinstance(value, list):
                for i, elem in enumerate(value):
                    if isinstance(elem, basestring):
                        value[i] = _resolve_single_value(
                            awsclient, elem, stacks, lookups, is_yugen)
                    else:
                        _resolve_lookups_recurse(
                            awsclient, elem, stacks, lookups, is_yugen)
            else:
                config[key] = _resolve_single_value(
                    awsclient, value, stacks, lookups, is_yugen)


def _resolve_single_value(awsclient, value, stacks, lookups, is_yugen=False):
    # split lookup in elements and resolve the lookup using servicediscovery
    if isinstance(value, basestring):
        if value.startswith('lookup:'):
            splits = value.split(':')
            if splits[1] == 'stack' and 'stack' in lookups:
                if not stack_exists(awsclient, splits[2]):
                    raise Exception('Stack \'%s\' does not exist.' % splits[2])
                if len(splits) == 3:
                    # lookup:stack:<stack-name>
                    return stacks[splits[2]]
                elif len(splits) == 4:
                    # lookup:stack:<stack-name>:<output-name>
                    return stacks[splits[2]][splits[3]]
                else:
                    log.warn('lookup format not as expected for \'%s\'', value)
                    return value
            elif splits[1] == 'ssl' and 'ssl' in lookups:
                return list(stacks[splits[2]].values())[0]
            elif splits[1] == 'secret' and 'secret' in lookups:
                try:
                    return get_secret(awsclient, splits[2])
                except ItemNotFound as e:
                    if len(splits) > 3 and splits[3] == 'CONTINUE_IF_NOT_FOUND':
                        log.warning('lookup:secret \'%s\' not found in credstash!', splits[2])
                    else:
                        raise e
            elif splits[1] == 'acm' and 'acm' in lookups:
                cert = _acm_lookup(awsclient, splits[2:], is_yugen)
                if cert:
                    return cert
                else:
                    raise Exception('no ACM certificate matches your query, sorry')

    return value


def _identify_stacks_recurse(config, lookups):
    """identify all stacks which we need to fetch (unique)
    cant say why but this list contains also certificates

    :param config:
    :return:
    """
    def _identify_single_value(value, stacklist, lookups):
        if isinstance(value, basestring):
            if value.startswith('lookup:'):
                splits = value.split(':')
                if splits[1] == 'stack' and 'stack' in lookups:
                    stacklist.append(splits[2])
                elif splits[1] == 'ssl' and 'ssl' in lookups:
                    stacklist.append(splits[2])

    stacklist = []
    if isinstance(config, dict):
        for key, value in config.items():
            if isinstance(value, dict):
                stacklist += _identify_stacks_recurse(value, lookups)
            elif isinstance(value, list):
                for elem in value:
                    stacklist.extend(_identify_stacks_recurse(elem, lookups))
            else:
                _identify_single_value(value, stacklist, lookups)
    else:
        _identify_single_value(config, stacklist, lookups)
    return set(stacklist)


def _acm_lookup(awsclient, names, is_yugen=False):
    """Execute the actual ACM lookup

    :param awsclient:
    :param names: list of fqdn and hosted zones
    :param is_yugen: for API Gateway we need to lookup the certs from us-east-1
    :return:
    """
    if is_yugen:
        # for API Gateway we need to lookup the certs from us-east-1
        # set region to `us-east-1`
        client_acm = awsclient.get_client('acm', 'us-east-1')
    else:
        client_acm = awsclient.get_client('acm')

    # get all certs in issued state
    response = client_acm.list_certificates(
        CertificateStatuses=['ISSUED'],
        MaxItems=200
    )
    # list of 'CertificateArn's
    issued_list = [e['CertificateArn'] for e in response['CertificateSummaryList']]
    log.debug('found %d issued certificates', len(issued_list))

    # collect the cert details
    certs = []
    for cert_arn in issued_list:
        response = client_acm.describe_certificate(
            CertificateArn=cert_arn
        )
        if 'Certificate' in response:
            cert = response['Certificate']
            all_names = cert.get('SubjectAlternativeNames', [])
            if 'DomainName' in cert and cert['DomainName'] not in all_names:
                all_names.append(cert['DomainName'])
            certs.append({
                'CertificateArn': cert_arn,
                'Names': all_names,
                'NotAfter': cert['NotAfter']
            })

    return _find_matching_certificate(certs, names)


def _find_matching_certificate(certs, names):
    """helper to find the first matching certificate with the most distant expiry date

    :param certs: list of certs
    :param names: list of names
    :return: arn if found
    """

    # sort by 'NotAfter' to get `most distant expiry date` first
    certs_ordered = sorted(certs, key=lambda k: k['NotAfter'], reverse=True)

    # take the first cert that fits our search criteria
    for cert in certs_ordered:
        matches = True
        for name in names:
            if name.startswith('*.'):
                if name in cert['Names']:
                    continue
                else:
                    matches = False
                    break
            else:
                if name in cert['Names']:
                    continue
                elif '*.' + name.split('.', 1)[1] in cert['Names']:
                    # host name contained in wildcard
                    continue
                else:
                    matches = False
                    break
        if matches:
            # found it!
            return cert['CertificateArn']

    # no certificate matches your query, sorry
    return


def lookup(params):
    """lookups.
    :param params: context, config (context - the _awsclient, etc..
                   config - The stack details, etc..)
    """
    context, config = params
    try:
        defaults = get_plugin_defaults(config, 'gcdt_lookups')
        _resolve_lookups(context, config, defaults.get('lookups', []))
    except GracefulExit:
        raise
    except Exception as e:
        context['error'] = str(e)
        log.error(context['error'])


def incept_defaults(params):
    """incept defaults where needed (after config is read from file).
    :param params: context, config (context - the _awsclient, etc..
                   config - The stack details, etc..)
    """
    incept_defaults_helper(params, read_openapi(), 'gcdt_lookups', True)


def validate_config(params):
    """validate the config after lookups.
    :param params: context, config (context - the _awsclient, etc..
                   config - The stack details, etc..)
    """
    validate_config_helper(params, read_openapi(), 'gcdt_lookups', True)


def register():
    """Please be very specific about when your plugin needs to run and why.
    E.g. run the sample stuff after at the very beginning of the lifecycle
    """
    gcdt_signals.config_read_finalized.connect(incept_defaults)
    gcdt_signals.config_validation_init.connect(validate_config)
    gcdt_signals.lookup_init.connect(lookup)


def deregister():
    gcdt_signals.config_read_finalized.disconnect(incept_defaults)
    gcdt_signals.config_validation_init.disconnect(validate_config)
    gcdt_signals.lookup_init.disconnect(lookup)
