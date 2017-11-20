# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

import pytest

from gcdt_testtools.helpers_aws import check_preconditions, check_normal_mode
from gcdt_testtools.helpers_aws import awsclient  # fixtures!
from gcdt_lookups.lookups import _acm_lookup


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
