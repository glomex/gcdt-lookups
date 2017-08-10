# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

import pytest

from gcdt_testtools.helpers_aws import check_preconditions, check_normal_mode
from gcdt_testtools.helpers_aws import awsclient  # fixtures!
from gcdt_lookups.lookups import _acm_lookup


@pytest.mark.aws
@check_preconditions
@check_normal_mode
def test_acm_lookup(awsclient):
    # we decided to not use placebo recording for this testcase
    # * if we deploy new certificates this might break
    # * we do not want to have all the certificate details in github
    host_list = ['*.infra.glomex.cloud', '*.dev.infra.glomex.cloud']
    assert _acm_lookup(awsclient, host_list) is not None
