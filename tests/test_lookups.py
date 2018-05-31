# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function
import logging

import maya
import mock

from gcdt_testtools.helpers import logcapture
from gcdt_lookups.lookups import _resolve_lookups, _identify_stacks_recurse, \
    lookup, _find_matching_certificate, _acm_lookup
from gcdt_lookups.credstash_utils import ItemNotFound
from gcdt.gcdt_defaults import CONFIG_READER_CONFIG


def test_identify_stacks_recurse():
    # make sure result is unique
    # sample from data-platform, ingest
    config = {
        'PolicyLambdaDefaultVar' : "lookup:stack:dp-dev-operations-common:PolicyLambdaDefault",
        'PolicyLambdaDefaultVar2': "lookup:stack:dp-dev-operations-common:PolicyLambdaDefault"
    }
    assert _identify_stacks_recurse(config, ['stack']) == \
           set([('dp-dev-operations-common', None)])

    # sample from pnb-ftp, ftpbackend
    config = {
        'VpcId': "lookup:stack:pnb-dev:DefaultVPCId"
    }
    assert _identify_stacks_recurse(config, ['stack']) == set([('pnb-dev', None)])


@mock.patch('gcdt_lookups.lookups.get_outputs_for_stack')
@mock.patch('gcdt_lookups.lookups.stack_exists', return_value=True)
def test_stack_lookup_value(mock_stack_exists, mock_get_outputs_for_stack):
    mock_get_outputs_for_stack.return_value = {
        'EC2BasicsLambdaArn':
            'arn:aws:lambda:eu-west-1:1122233:function:dp-preprod-lambdaEC2Basics-12',
    }
    # sample from data-platform, operations
    context = {
        '_awsclient': 'my_awsclient',
        'tool': 'ramuda'
    }

    config = {
        'LambdaLookupARN': 'lookup:stack:dp-preprod:EC2BasicsLambdaArn'
    }
    _resolve_lookups(context, config, ['stack'])
    mock_get_outputs_for_stack.assert_called_once_with(
        'my_awsclient', 'dp-preprod', None)

    assert config.get('LambdaLookupARN') == \
           'arn:aws:lambda:eu-west-1:1122233:function:dp-preprod-lambdaEC2Basics-12'

@mock.patch('gcdt_lookups.lookups.get_outputs_for_stack')
@mock.patch('gcdt_lookups.lookups.stack_exists', return_value=False)
def test_stack_lookup_optional_value(mock_stack_exists, mock_get_outputs_for_stack):
    # sample from data-platform, operations
    context = {
        '_awsclient': 'my_awsclient',
        'tool': 'ramuda'
    }

    config = {
        'LambdaLookupARN': 'lookup:stack:non-existing-stack:NonExistingValue:optional'
    }
    _resolve_lookups(context, config, ['stack'])

    assert config.get('LambdaLookupARN') == ''


@mock.patch('gcdt_lookups.lookups.get_outputs_for_stack')
@mock.patch('gcdt_lookups.lookups.stack_exists', return_value=True)
def test_stack_lookup_stack_output(mock_stack_exists,
                                   mock_get_outputs_for_stack):
    # lookup:stack:<stack_name> w/o value gets us the whole stack_output
    stack_output = {
        'EC2BasicsLambdaArn':
            'arn:aws:lambda:eu-west-1:1122233:function:dp-preprod-lambdaEC2Basics-12',
    }
    mock_get_outputs_for_stack.return_value = stack_output
    # sample from data-platform, operations
    context = {
        '_awsclient': 'my_awsclient',
        'tool': 'ramuda'
    }

    config = {
        'stack_output': 'lookup:stack:dp-preprod'
    }
    _resolve_lookups(context, config, ['stack'])
    mock_get_outputs_for_stack.assert_called_once_with(
        'my_awsclient', 'dp-preprod', None)

    assert config.get('stack_output') == stack_output


@mock.patch('gcdt_lookups.lookups.get_base_ami',
            return_value='img-123456')
def test_baseami_lookup(mock_get_base_ami):
    # sample from mes-ftp, ftpbackend
    context = {
        '_awsclient': 'my_awsclient',
        'tool': 'kumo'
    }
    config = {
        'BaseAMIID': 'lookup:baseami'
    }
    _resolve_lookups(context, config, ['baseami'])
    mock_get_base_ami.assert_called_once_with(
        'my_awsclient', ['569909643510'])

    assert config.get('BaseAMIID') == 'img-123456'


@mock.patch('gcdt_lookups.lookups.get_outputs_for_stack')
@mock.patch('gcdt_lookups.lookups.get_ssl_certificate')
def test_read_config_mock_service_discovery_ssl(
        mock_get_ssl_certificate, mock_get_outputs_for_stack):
    mock_get_outputs_for_stack.return_value = {
        'DefaultInstancePolicyARN':
            'arn:aws:bla:blub',
    }
    # Mock Output (List SSL Certs)
    mock_get_ssl_certificate.return_value = 'arn:aws:iam::11:server-certificate/cloudfront/2016/wildcard.dp.glomex.cloud-2016-03'
    # sample from mes-proxy
    context = {
        '_awsclient': 'my_awsclient',
        'tool': 'ramuda'
    }
    config = {
        'DefaultInstancePolicyARN': 'lookup:stack:portal-dev:DefaultInstancePolicyARN',
        'SSLCert': 'lookup:ssl:wildcard.glomex.com'
    }

    _resolve_lookups(context, config, ['ssl', 'stack'])
    mock_get_outputs_for_stack.assert_called_once_with(
        'my_awsclient', 'portal-dev', None)
    mock_get_ssl_certificate.assert_called_once_with(
        'my_awsclient', 'wildcard.glomex.com')
    assert config.get('SSLCert') == \
           'arn:aws:iam::11:server-certificate/cloudfront/2016/wildcard.dp.glomex.cloud-2016-03'


# tests taken and modified from former config_reader tests
@mock.patch('gcdt_lookups.lookups.get_ssl_certificate')
@mock.patch('gcdt_lookups.lookups.get_secret')
@mock.patch('gcdt_lookups.lookups.get_outputs_for_stack')
@mock.patch('gcdt_lookups.lookups.stack_exists', return_value=True)
def test_lookup_selective_stack_lookup_all_lookups(
        mock_stack_exists,
        mock_get_outputs_for_stack, mock_get_secret,
        mock_get_ssl_certificate):
    # Mock Output (Credstash result)
    mock_get_secret.return_value = 'secretPassword'
    # Mock Output (SSL Cert)
    mock_get_ssl_certificate.return_value = 'arn:aws:iam::11:server-certificate/cloudfront/2016/wildcard.dp.glomex.cloud-2016-03'
    # Mock Output (Desc Stack)
    mock_get_outputs_for_stack.return_value = {
        'EC2BasicsLambdaArn': 'arn:aws:lambda:eu-west-1:1122233:function:dp-preprod-lambdaEC2Basics-12',
    }

    context = {
        '_awsclient': 'my_awsclient',
        'tool': 'kumo'
    }
    config = {
        'secret': 'lookup:secret:nameOfSecretPassword',
        'sslCert': 'lookup:ssl:wildcard.dp.glomex.cloud-2016-03',
        'stack': 'lookup:stack:dp-preprod:EC2BasicsLambdaArn'
    }

    _resolve_lookups(context, config, ['ssl', 'stack', 'secret'])

    assert config.get('secret') == 'secretPassword'
    assert config.get('sslCert') == \
           'arn:aws:iam::11:server-certificate/cloudfront/2016/wildcard.dp.glomex.cloud-2016-03'
    assert config.get('stack') == \
           'arn:aws:lambda:eu-west-1:1122233:function:dp-preprod-lambdaEC2Basics-12'


# I split the combined testcases into seperate instances
# sorry if this is a little c&p
@mock.patch('gcdt_lookups.lookups.get_ssl_certificate')
@mock.patch('gcdt_lookups.lookups.get_secret')
@mock.patch('gcdt_lookups.lookups.get_outputs_for_stack')
@mock.patch('gcdt_lookups.lookups.stack_exists', return_value=True)
def test_lookup_selective_stack_lookup_limit_to_stack_lookup(
        mock_stack_exists,
        mock_get_outputs_for_stack, mock_get_secret,
        mock_get_ssl_certificate):
    # Mock Output (Credstash result)
    mock_get_secret.return_value = 'secretPassword'
    # Mock Output (SSL Cert)
    mock_get_ssl_certificate.return_value = 'arn:aws:iam::11:server-certificate/cloudfront/2016/wildcard.dp.glomex.cloud-2016-03'
    # Mock Output (Desc Stack)
    mock_get_outputs_for_stack.return_value = {
        'EC2BasicsLambdaArn': 'arn:aws:lambda:eu-west-1:1122233:function:dp-preprod-lambdaEC2Basics-12',
    }

    context = {
        '_awsclient': 'my_awsclient',
        'tool': 'ramuda'
    }
    config = {
        'secret': 'lookup:secret:nameOfSecretPassword',
        'sslCert': 'lookup:ssl:wildcard.dp.glomex.cloud-2016-03',
        'stack': 'lookup:stack:dp-preprod:EC2BasicsLambdaArn'
    }

    _resolve_lookups(context, config, ['stack'])

    assert config.get('secret') == 'lookup:secret:nameOfSecretPassword'
    assert config.get('sslCert') == \
           'lookup:ssl:wildcard.dp.glomex.cloud-2016-03'
    assert config.get('stack') == \
           'arn:aws:lambda:eu-west-1:1122233:function:dp-preprod-lambdaEC2Basics-12'


@mock.patch('gcdt_lookups.lookups.get_ssl_certificate')
@mock.patch('gcdt_lookups.lookups.get_secret')
@mock.patch('gcdt_lookups.lookups.get_outputs_for_stack')
def test_lookup_selective_stack_lookup_limit_to_secret_lookup(
        mock_get_outputs_for_stack, mock_get_secret,
        mock_get_ssl_certificate):
    # Mock Output (Credstash result)
    mock_get_secret.return_value = 'secretPassword'
    # Mock Output (SSL Cert)
    mock_get_ssl_certificate.return_value = 'arn:aws:iam::11:server-certificate/cloudfront/2016/wildcard.dp.glomex.cloud-2016-03'
    # Mock Output (Desc Stack)
    mock_get_outputs_for_stack.return_value = {
        'EC2BasicsLambdaArn': 'arn:aws:lambda:eu-west-1:1122233:function:dp-preprod-lambdaEC2Basics-12',
    }

    context = {
        '_awsclient': 'my_awsclient',
        'tool': 'kumo'
    }
    config = {
        'secret': 'lookup:secret:nameOfSecretPassword',
        'sslCert': 'lookup:ssl:wildcard.dp.glomex.cloud-2016-03',
        'stack': 'lookup:stack:dp-preprod:EC2BasicsLambdaArn'
    }

    _resolve_lookups(context, config, ['secret'])

    assert config.get('secret') == 'secretPassword'
    assert config.get('sslCert') == \
           'lookup:ssl:wildcard.dp.glomex.cloud-2016-03'
    assert config.get('stack') == \
           'lookup:stack:dp-preprod:EC2BasicsLambdaArn'


@mock.patch('gcdt_lookups.lookups.get_ssl_certificate')
@mock.patch('gcdt_lookups.lookups.get_secret')
@mock.patch('gcdt_lookups.lookups.get_outputs_for_stack')
def test_lookup_selective_stack_lookup_limit_to_ssl_lookup(
        mock_get_outputs_for_stack, mock_get_secret,
        mock_get_ssl_certificate):
    # Mock Output (Credstash result)
    mock_get_secret.return_value = 'secretPassword'
    # Mock Output (SSL Cert)
    mock_get_ssl_certificate.return_value = 'arn:aws:iam::11:server-certificate/cloudfront/2016/wildcard.dp.glomex.cloud-2016-03'
    # Mock Output (Desc Stack)
    mock_get_outputs_for_stack.return_value = {
        'EC2BasicsLambdaArn': 'arn:aws:lambda:eu-west-1:1122233:function:dp-preprod-lambdaEC2Basics-12',
    }

    context = {
        '_awsclient': 'my_awsclient',
        'tool': 'ramuda'
    }
    config = {
        'secret': 'lookup:secret:nameOfSecretPassword',
        'sslCert': 'lookup:ssl:wildcard.dp.glomex.cloud-2016-03',
        'stack': 'lookup:stack:dp-preprod:EC2BasicsLambdaArn'
    }

    _resolve_lookups(context, config, ['ssl'])

    assert config.get('secret') == 'lookup:secret:nameOfSecretPassword'
    assert config.get('sslCert') == \
           'arn:aws:iam::11:server-certificate/cloudfront/2016/wildcard.dp.glomex.cloud-2016-03'
    assert config.get('stack') == \
           'lookup:stack:dp-preprod:EC2BasicsLambdaArn'


@mock.patch('gcdt_lookups.lookups.get_base_ami')
@mock.patch('gcdt_lookups.lookups.get_outputs_for_stack')
@mock.patch('gcdt_lookups.lookups.stack_exists', return_value=True)
def test_lookup_kumo_sample(
        mock_stack_exists,
        mock_get_outputs_for_stack,
        mock_get_base_ami):
    mock_get_base_ami.return_value = 'ami-91307fe2'
    mock_get_outputs_for_stack.return_value = {
        'DefaultInstancePolicyARN': 'arn:aws:iam::420189626185:policy/7f-managed/infra-dev-Defaultmanagedinstancepolicy-9G6XX1YXZI5O',
        'DefaultVPCId': 'vpc-88d2a7ec',
    }

    context = {
        '_awsclient': 'my_awsclient',
        'tool': 'kumo'
    }
    config = {
        'kumo': {
            'stack': {
                'StackName': 'gcdt-sample-stack',
            },
            'parameters': {
                'VPCId': 'vpc-88d2a7ec',
                'ScaleMinCapacity': '1',
                'ScaleMaxCapacity': '1',
                'InstanceType': 't2.micro',
                'ELBDNSName': 'supercars',
                'BaseStackName': 'infra-dev',
                'DefaultInstancePolicyARN': 'lookup:stack:infra-dev:DefaultInstancePolicyARN',
                'AMI': 'lookup:baseami'
            }
        }
    }

    _resolve_lookups(context, config, ['ssl', 'stack', 'secret', 'baseami'])

    assert config['kumo'] == {
        'stack': {
            'StackName': 'gcdt-sample-stack',
        },
        'parameters': {
            'VPCId': 'vpc-88d2a7ec',
            'ScaleMinCapacity': '1',
            'ScaleMaxCapacity': '1',
            'InstanceType': 't2.micro',
            'ELBDNSName': 'supercars',
            'BaseStackName': 'infra-dev',
            'DefaultInstancePolicyARN': 'arn:aws:iam::420189626185:policy/7f-managed/infra-dev-Defaultmanagedinstancepolicy-9G6XX1YXZI5O',
            'AMI': 'ami-91307fe2'
        }
    }


@mock.patch('gcdt_lookups.lookups.get_secret',
            return_value='foobar1234')
def test_secret_lookup(mock_get_secret):
    # sample from ops-captaincrunch-slack
    context = {
        '_awsclient': 'my_awsclient',
        'tool': 'ramuda'
    }
    config = {
        'bot_token': 'lookup:secret:captaincrunch.bot_token'
    }
    _resolve_lookups(context, config, ['secret'])
    mock_get_secret.assert_called_once_with(
        'my_awsclient', 'captaincrunch.bot_token', region_name=None)

    assert config.get('bot_token') == 'foobar1234'


@mock.patch('gcdt_lookups.lookups.get_secret',
            return_value='foobar1234')
def test_secret_lookup_continue_if_not_found(mock_get_secret, logcapture):
    logcapture.level = logging.INFO
    mock_get_secret.side_effect = ItemNotFound('not found, sorry')
    context = {
        '_awsclient': 'my_awsclient',
        'tool': 'ramuda'
    }
    config = {
        'bazz_value': 'lookup:secret:foo.bar.bazz:CONTINUE_IF_NOT_FOUND'
    }
    _resolve_lookups(context, config, ['secret'])
    mock_get_secret.assert_called_once_with(
        'my_awsclient', 'foo.bar.bazz', region_name=None)

    assert config.get('bazz_value') == \
           'lookup:secret:foo.bar.bazz:CONTINUE_IF_NOT_FOUND'

    records = list(logcapture.actual())
    assert records[0][1] == 'WARNING'
    assert records[0][2] == \
           'lookup:secret \'foo.bar.bazz\' not found in credstash!'


@mock.patch('gcdt_lookups.lookups.get_secret',
            return_value='foobar1234')
def test_secret_lookup_error_case(mock_get_secret, logcapture):
    logcapture.level = logging.INFO
    mock_get_secret.side_effect = ItemNotFound('not found, sorry')
    context = {
        '_awsclient': 'my_awsclient',
        'tool': 'ramuda'
    }
    config = {
        'lookups': ['secret'],
        'bazz_value': 'lookup:secret:foo.bar.bazz'
    }
    lookup((context, config))
    mock_get_secret.assert_called_once_with(
        'my_awsclient', 'foo.bar.bazz', region_name=None)
    assert context['error'] == \
        'lookup for \'bazz_value\' failed: "lookup:secret:foo.bar.bazz"'
    assert config.get('bazz_value') == \
        'lookup:secret:foo.bar.bazz'

    assert context['error'] == \
        'lookup for \'bazz_value\' failed: "lookup:secret:foo.bar.bazz"'
    records = list(logcapture.actual())
    assert records[0][1] == 'ERROR'
    assert records[0][2] == 'not found, sorry'


def test_ami_accountid_config():
    ami_accountid = CONFIG_READER_CONFIG['plugins']['gcdt_lookups'][
        'ami_accountid']
    assert ami_accountid == '569909643510'


def test_find_matching_certificate():
    names = ['infra.glomex.cloud', '*.infra.glomex.cloud']
    expected = 'arn:aws:acm:eu-west-1:123456789012:certificate/klmno-123'

    certs = [
        {
            'CertificateArn': 'arn:aws:acm:eu-west-1:123456789012:certificate/abcde-123',
            'Names': ['*.infra.glomex.cloud', 'infra.glomex.cloud',
                      '*.infra.glomex.cloud'],
            'NotAfter': maya.now().add(months=1).datetime()
        },
        {
            'CertificateArn': 'arn:aws:acm:eu-west-1:123456789012:certificate/fghij-123',
            'Names': ['*.abc-vvs-test.glomex.com',
                      '*.abc-vvs.glomex.com', '*.dev.ds.glomex.cloud',
                      '*.dev.mds.glomex.cloud', '*.dev.mep.glomex.cloud',
                      '*.dev.mes.glomex.cloud', '*.dev.pnb.glomex.cloud',
                      '*.dev.vvs.glomex.cloud', '*.ds.glomex.cloud'],
            'NotAfter': maya.now().add(months=10).datetime()
        },
        {
            'CertificateArn': 'arn:aws:acm:eu-west-1:123456789012:certificate/klmno-123',
            'Names': ['*.infra.glomex.cloud', 'infra.glomex.cloud',
                      '*.infra.glomex.cloud'],
            'NotAfter': maya.now().add(months=20).datetime()
        },
    ]
    assert _find_matching_certificate(certs, names) == expected


def test_find_matching_certificate_not_found():
    logcapture.level = logging.INFO
    names = ['unknown.glomex.cloud', '*.infra.glomex.cloud']

    certs = [
        {
            'CertificateArn': 'arn:aws:acm:eu-west-1:123456789012:certificate/abcde-123',
            'Names': ['*.infra.glomex.cloud', 'infra.glomex.cloud',
                      '*.infra.glomex.cloud'],
            'NotAfter': maya.now().add(months=1).datetime()
        },
        {
            'CertificateArn': 'arn:aws:acm:eu-west-1:123456789012:certificate/fghij-123',
            'Names': ['*.abc-vvs-test.glomex.com',
                      '*.abc-vvs.glomex.com', '*.dev.ds.glomex.cloud',
                      '*.dev.mds.glomex.cloud', '*.dev.mep.glomex.cloud',
                      '*.dev.mes.glomex.cloud', '*.dev.pnb.glomex.cloud',
                      '*.dev.vvs.glomex.cloud', '*.ds.glomex.cloud'],
            'NotAfter': maya.now().add(months=10).datetime()
        },
        {
            'CertificateArn': 'arn:aws:acm:eu-west-1:123456789012:certificate/klmno-123',
            'Names': ['*.infra.glomex.cloud', 'infra.glomex.cloud',
                      '*.infra.glomex.cloud'],
            'NotAfter': maya.now().add(months=20).datetime()
        },
    ]
    assert _find_matching_certificate(certs, names) is None


@mock.patch('gcdt_lookups.lookups.get_secret',
            return_value='foobar1234')
def test_region_secret_lookup(mock_get_secret):
    # sample from ops-captaincrunch-slack
    context = {
        '_awsclient': 'my_awsclient',
        'tool': 'ramuda'
    }
    config = {
        'bot_token': 'lookup:secret:captaincrunch.bot_token'
    }
    _resolve_lookups(context, config, ['secret'])
    mock_get_secret.assert_called_once_with(
        'my_awsclient', 'captaincrunch.bot_token', region_name=None)

    assert config.get('bot_token') == 'foobar1234'
