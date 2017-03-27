# -*- coding: utf-8 -*-
"""This file contains configuration for gcdt tools so we do not need
hardcoded values.
"""
from __future__ import unicode_literals, print_function

# basic structure:
'''
{
    'kumo': {},
    'tenkai': {},
    'ramuda': {},
    'yugen': {},
    'plugins': {
        '<plugin_name>': {}
    }
}
'''


# note this config is used in the glomex_config_reader to "overlay" the
# gcdt_defaults of gcdt.
DEFAULT_CONFIG = {
    'lookups': ['secret', 'ssl', 'stack', 'baseami'],
    'plugins': {
        'datadog_integration': {
            'datadog_api_key': 'lookup:secret:datadog.api_key'
        },
        'slack_integration': {
            'slack_webhook': 'lookup:secret:slack.webhook:CONTINUE_IF_NOT_FOUND'
        },
        'glomex_lookups': {
            'ami_accountid': '569909643510'
        }
    }
}
