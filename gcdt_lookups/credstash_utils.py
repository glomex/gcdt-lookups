# -*- coding: utf-8 -*-
"""Common functionality used in multiple glomex gcdt plugins.
"""

from __future__ import unicode_literals, print_function

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Hash.HMAC import HMAC
from Crypto.Util import Counter

import botocore.exceptions
from gcdt.utils import GracefulExit


# needed to be copied from credstash in order to make it work with awsclient
class KmsError(Exception):
    def __init__(self, value=""):
        self.value = "KMS ERROR: " + value if value is not "" else "KMS ERROR"

    def __str__(self):
        return self.value


class IntegrityError(Exception):
    def __init__(self, value=""):
        self.value = "INTEGRITY ERROR: " + value if value is not "" else \
            "INTEGRITY ERROR"

    def __str__(self):
        return self.value


class ItemNotFound(Exception):
    pass


def get_secret(awsclient, name, version="",  # region=None,
                table="credential-store", context=None,
               **kwargs):
    '''
    fetch and decrypt the secret called `name`
    '''
    if context is None:
        context = {}
    client_ddb = awsclient.get_client('dynamodb')

    if version == "":
        # do a consistent fetch of the credential with the highest version
        # note KeyConditionExpression: Key("name").eq(name))
        response = client_ddb.query(
            TableName=table,
            Limit=1,
            ScanIndexForward=False,
            ConsistentRead=True,
            KeyConditionExpression='#S = :val',
            ExpressionAttributeNames={'#S': 'name'},
            ExpressionAttributeValues={':val': {'S': name}}
        )
        if response["Count"] == 0:
            raise ItemNotFound("Item {'name': '%s'} couldn't be found." % name)
        material = response["Items"][0]
    else:
        response = client_ddb.get_item(
            TableName=table,
            Key={
                "name": {'S': name},
                "version": {'S': version}
                }
        )
        if "Item" not in response:
            raise ItemNotFound(
                "Item {'name': '%s', 'version': '%s'} couldn't be found." % (
                    name, version))
        material = response["Item"]

    kms = awsclient.get_client('kms')
    # Check the HMAC before we decrypt to verify ciphertext integrity
    try:
        kms_response = kms.decrypt(CiphertextBlob=b64decode(material['key']['S']),
                                   EncryptionContext=context)

    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "InvalidCiphertextException":
            if context is None:
                msg = (
                    "Could not decrypt hmac key with KMS. The credential may "
                    "require that an encryption context be provided to decrypt "
                    "it.")
            else:
                msg = ("Could not decrypt hmac key with KMS. The encryption "
                       "context provided may not match the one used when the "
                       "credential was stored.")
        else:
            msg = "Decryption error %s" % e
        raise KmsError(msg)
    except GracefulExit:
        raise
    except Exception as e:
        raise KmsError("Decryption error %s" % e)
    key = kms_response['Plaintext'][:32]
    hmac_key = kms_response['Plaintext'][32:]
    hmac = HMAC(hmac_key, msg=b64decode(material['contents']['S']),
                digestmod=SHA256)
    if hmac.hexdigest() != material['hmac']['S']:
        raise IntegrityError("Computed HMAC on %s does not match stored HMAC"
                             % name)
    dec_ctr = Counter.new(128)
    decryptor = AES.new(key, AES.MODE_CTR, counter=dec_ctr)
    plaintext = decryptor.decrypt(b64decode(material['contents']['S'])).decode(
        "utf-8")
    return plaintext
