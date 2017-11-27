# -*- coding: utf-8 -*-
"""A gcdt plugin to do lookups."""
from __future__ import unicode_literals, print_function
import sys
import json

from botocore.exceptions import ClientError
from gcdt import gcdt_signals
from gcdt.servicediscovery import get_ssl_certificate, \
    get_base_ami
from gcdt.gcdt_logging import getLogger
from gcdt.gcdt_awsclient import ClientError
from gcdt.gcdt_defaults import CONFIG_READER_CONFIG
from gcdt.utils import GracefulExit


from .credstash_utils import get_secret, ItemNotFound

PY3 = sys.version_info[0] >= 3

if PY3:
    basestring = str

log = getLogger(__name__)

GCDT_TOOLS = ['kumo', 'tenkai', 'ramuda', 'yugen']


# copied over from gcdt.servicediscovery so we can change it locally
# TODO add region_name parameter feature back to gcdt
def get_outputs_for_stack(awsclient, stack_name, region_name=None):
    """
    Read environment from ENV and mangle it to a (lower case) representation
    Note: gcdt.servicediscovery get_outputs_for_stack((awsclient, stack_name)
    is used in many cloudformation.py templates!

    :param awsclient:
    :param stack_name:
    :param region_name:
    :return: dictionary containing the stack outputs
    """
    client_cf = awsclient.get_client('cloudformation', region_name)
    response = client_cf.describe_stacks(StackName=stack_name)
    if response['Stacks'] and 'Outputs' in response['Stacks'][0]:
        result = {}
        for output in response['Stacks'][0]['Outputs']:
            result[output['OutputKey']] = output['OutputValue']
        return result


# copied over from gcdt.kumo_core so we can change it locally
# TODO add region_name parameter feature back to gcdt
def stack_exists(awsclient, stack_name, region_name=None):
    client = awsclient.get_client('cloudformation', region_name)
    try:
        response = client.describe_stacks(
            StackName=stack_name
        )
    except GracefulExit:
        raise
    except Exception:
        return False
    else:
        return True


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

    for stack, region_name in stackset:
        # with the '.' you can distinguish between a stack and a certificate
        if '.' in stack and 'ssl' in lookups:
            stackdata.update({
                stack: {
                    'sslcert': get_ssl_certificate(awsclient, stack)
                }
            })
        elif 'stack' in lookups:
            try:
                stackdata.update({
                    stack: get_outputs_for_stack(awsclient, stack, region_name)
                })
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


def _get_lookup_details(value):
    # helper to extract details
    # TODO use openapi to verify lookup format is correct
    splits = value.split(':')
    region = None
    lookup_type = splits[1]
    key = splits[2:]
    if lookup_type == 'region':
        region = splits[2]
        lookup_type = splits[3]
        key = splits[4:]
    if len(key) == 1:
        key = key[0]  # unpack
    return region, lookup_type, key


def _resolve_single_value(awsclient, value, stacks, lookups, is_yugen=False):
    # split lookup in elements and resolve the lookup using servicediscovery
    if isinstance(value, basestring):
        if value.startswith('lookup:'):
            region_name, lt, key = _get_lookup_details(value)
            if region_name is not None:
                log.debug('executing lookup \'%s\' in \'%s\' region' % (lt, region_name))
            if lt == 'stack' and 'stack' in lookups:
                if isinstance(key, list):
                    if not stack_exists(awsclient, key[0], region_name):
                        raise Exception('Stack \'%s\' does not exist.' % key[0])
                    if len(key) == 2:
                        # lookup:stack:<stack-name>:<output-name>
                        return stacks[key[0]][key[1]]
                    else:
                        log.warn('lookup format not as expected for \'%s\'', value)
                        return value
                else:
                    if not stack_exists(awsclient, key, region_name):
                        raise Exception('Stack \'%s\' does not exist.' % key)
                    # lookup:stack:<stack-name>
                    return stacks[key]
            elif lt == 'ssl' and 'ssl' in lookups:
                return list(stacks[key].values())[0]
            elif lt == 'secret' and 'secret' in lookups:
                try:
                    if isinstance(key, list):
                        return get_secret(awsclient, key[0], region_name=region_name)
                    return get_secret(awsclient, key, region_name=region_name)
                except ItemNotFound as e:
                    if isinstance(key, list) and key[-1] == 'CONTINUE_IF_NOT_FOUND':
                        log.warning('lookup:secret \'%s\' not found in credstash!', key[0])
                    else:
                        raise e
            elif lt == 'baseami' and 'baseami' in lookups:
                # DEPRECATED baseami lookup (21.07.2017)
                ami_accountid = CONFIG_READER_CONFIG['plugins']['gcdt_lookups']['ami_accountid']
                return get_base_ami(awsclient, [ami_accountid])
            elif lt == 'acm' and 'acm' in lookups:
                if is_yugen:
                    # for API Gateway we need to lookup the certs from us-east-1
                    # set region to `us-east-1`
                    cert = _acm_lookup(awsclient, [key], region_name='us-east-1')
                else:
                    cert = _acm_lookup(awsclient, [key], region_name=region_name)
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
                region_name, lt, key = _get_lookup_details(value)
                if lt in lookups:
                    if key and isinstance(key, list):
                        key = key[0]  # unpack to lookup stack output, not a value!
                    if lt in ['stack', 'ssl']:
                        stacklist.append(tuple([key, region_name]))

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


def _acm_lookup(awsclient, names, region_name=None):
    """Execute the actual ACM lookup

    :param awsclient:
    :param names: list of fqdn and hosted zones
    :param is_yugen: for API Gateway we need to lookup the certs from us-east-1
    :return:
    """
    client_acm = awsclient.get_client('acm', region_name)

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
                elif '.' in name and '*.' + name.split('.', 1)[1] in cert['Names']:
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
        _resolve_lookups(context, config, config.get('lookups', []))
    except GracefulExit:
        raise
    except Exception as e:
        context['error'] = str(e)


def register():
    """Please be very specific about when your plugin needs to run and why.
    E.g. run the sample stuff after at the very beginning of the lifecycle
    """
    gcdt_signals.lookup_init.connect(lookup)


def deregister():
    gcdt_signals.lookup_init.disconnect(lookup)
