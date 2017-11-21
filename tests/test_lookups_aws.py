# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

import pytest

from gcdt_testtools.helpers_aws import check_preconditions, check_normal_mode
from gcdt_testtools.helpers_aws import awsclient  # fixtures!
from gcdt_lookups.lookups import _acm_lookup, _resolve_lookups


@pytest.mark.aws
@check_preconditions
def test_acm_lookup(awsclient):
    # we decided to use placebo recording for this testcase since the certificate
    # information is public anyway
    # * if we deploy new certificates this might break
    # * we do not want to have all the certificate details in github
    host_list = ['*.infra.glomex.cloud', '*.dev.infra.glomex.cloud']
    cert_arn = _acm_lookup(awsclient, host_list)
    assert cert_arn is not None
    assert cert_arn.split(':')[3] == 'eu-west-1'


@pytest.mark.aws
@check_preconditions
def test_acm_lookup_is_yugen(awsclient):
    # for API Gateway certs need to come from us-east-1
    host_list = ['*.infra.glomex.cloud', '*.dev.infra.glomex.cloud']
    cert_arn = _acm_lookup(awsclient, host_list, 'us-east-1')
    assert cert_arn is not None
    assert cert_arn.split(':')[3] == 'us-east-1'


@pytest.mark.aws
@check_preconditions
def test_stack_lookup_stack_output(awsclient):
    # lookup:stack:<stack_name> w/o value gets us the whole stack_output
    context = {
        '_awsclient': awsclient,
        'tool': 'ramuda'
    }

    config = {
        'stack_output': 'lookup:stack:infra-dev'
    }
    _resolve_lookups(context, config, ['stack'])

    assert config.get('stack_output', {}).get('AWSAccountId') == '420189626185'


@pytest.mark.aws
@check_preconditions
def test_stack_lookup_value(awsclient):
    # lookup:stack:<stack_name> w/o value gets us the whole stack_output
    context = {
        '_awsclient': awsclient,
        'tool': 'ramuda'
    }

    config = {
        'AWSAccountId': 'lookup:stack:infra-dev:AWSAccountId'
    }
    _resolve_lookups(context, config, ['stack'])

    assert config.get('AWSAccountId') == '420189626185'


@pytest.mark.aws
@check_preconditions
@check_normal_mode
def test_secret_lookup(awsclient):
    context = {
        '_awsclient': awsclient,
        'tool': 'kumo'
    }
    config = {
        'BaseAMIID': 'lookup:secret:ops.dev.base_ami'
    }
    _resolve_lookups(context, config, ['secret'])

    assert config.get('BaseAMIID') == 'ami-1370b36a'
