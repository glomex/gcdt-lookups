# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

from gcdt.gcdt_openapi import get_defaults, get_scaffold_min, get_scaffold_max, \
    validate_tool_config

from gcdt_lookups import read_openapi


def test_default():
    spec = read_openapi()
    expected_defaults = {
        'defaults': {
            'validate': True,
            'lookups': ['secret', 'stack', 'acm']
        }
    }

    plugin_defaults = get_defaults(spec, 'gcdt_lookups')
    assert plugin_defaults == expected_defaults
    validate_tool_config(spec, {'plugins': {'gcdt_lookups': plugin_defaults}})
