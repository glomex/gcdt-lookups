# -*- coding: utf-8 -*-
"""A gcdt-plugin to do lookups."""
from __future__ import unicode_literals, print_function

from gcdt import gcdt_signals
from gcdt.servicediscovery import get_ssl_certificate, get_outputs_for_stack, \
    get_base_ami
from gcdt.gcdt_logging import getLogger
from gcdt.gcdt_awsclient import ClientError
from gcdt.kumo_core import stack_exists

from .credstash_utils import get_secret, ItemNotFound
from .gcdt_defaults import DEFAULT_CONFIG


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
                config[k] = _resolve_single_value(awsclient, config[k],
                                                  stackdata, lookups)
            else:
                _resolve_lookups_recurse(awsclient, config[k], stackdata, lookups)
        except Exception as e:
            if k in [t for t in GCDT_TOOLS if t != context['tool']]:
                # for "other" deployment phases & tools lookups can fail
                # ... which is quite normal!
                # only lookups for config['tool'] must not fail!
                pass
            else:
                log.debug(e.message, exc_info=True)  # this adds the traceback
                context['error'] = \
                    'lookup for \'%s\' failed (%s)' % (k, config[k])
                log.error(e.message)
                log.error(context['error'])


def _resolve_lookups_recurse(awsclient, config, stacks, lookups):
    # resolve inplace
    if isinstance(config, dict):
        for key, value in config.items():
            if isinstance(value, dict):
                _resolve_lookups_recurse(awsclient, value, stacks, lookups)
            elif isinstance(value, list):
                for i, elem in enumerate(value):
                    #_resolve_lookups_recurse(awsclient, elem, stacks, lookups)
                    if isinstance(elem, basestring):
                        value[i] = _resolve_single_value(awsclient, elem,
                                                         stacks, lookups)
                    else:
                        _resolve_lookups_recurse(awsclient, elem, stacks, lookups)
            else:
                config[key] = _resolve_single_value(awsclient, value,
                                                    stacks, lookups)


def _resolve_single_value(awsclient, value, stacks, lookups):
    # split lookup in elements and resolve the lookup using servicediscovery
    if isinstance(value, basestring):
        if value.startswith('lookup:'):
            splits = value.split(':')
            if splits[1] == 'stack' and 'stack' in lookups:
                if not stack_exists(awsclient, splits[2]):
                    raise Exception('Stack \'%s\' does not exist.' % splits[2])
                return stacks[splits[2]][splits[3]]
            elif splits[1] == 'ssl' and 'ssl' in lookups:
                return stacks[splits[2]].values()[0]
            elif splits[1] == 'secret' and 'secret' in lookups:
                try:
                    return get_secret(awsclient, splits[2])
                except ItemNotFound as e:
                    if len(splits) > 3 and splits[3] == 'CONTINUE_IF_NOT_FOUND':
                        log.warning('lookup:secret \'%s\' not found in credstash!', splits[2])
                    else:
                        raise e
            elif splits[1] == 'baseami' and 'baseami' in lookups:
                ami_accountid = DEFAULT_CONFIG['plugins']['gcdt_lookups']['ami_accountid']
                return get_base_ami(awsclient, [ami_accountid])
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


def lookup(params):
    """lookups.
    :param params: context, config (context - the _awsclient, etc..
                   config - The stack details, etc..)
    """
    context, config = params
    try:
        _resolve_lookups(context, config, config.get('lookups', []))
    except Exception as e:
        context['error'] = e.message


def register():
    """Please be very specific about when your plugin needs to run and why.
    E.g. run the sample stuff after at the very beginning of the lifecycle
    """
    gcdt_signals.lookup_init.connect(lookup)


def deregister():
    gcdt_signals.lookup_init.disconnect(lookup)
