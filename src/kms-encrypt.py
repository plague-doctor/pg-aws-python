#!/usr/bin/env python3

import boto3
import argparse
import sys
import os
import base64
import time


class color:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


##############################################################################
def aws_creds_expiry():
    return time.strftime('%Y-%m-%d %a %H:%M:%S', time.localtime(int(os.environ['AWS_CREDS_EXPIRY'])))


##############################################################################
def list_kms_keys():
    client = boto3.client('kms')
    response = client.list_keys()
    for key in response['Keys']:
        key_description = client.describe_key(
            KeyId=key['KeyId']
            )
        if ('CUSTOMER' in key_description['KeyMetadata']['KeyManager'] and
                'Enabled' in key_description['KeyMetadata']['KeyState'] and
                'ENCRYPT_DECRYPT' in key_description['KeyMetadata']['KeyUsage']):
            print("KeyId: {bold}{key}{reset} is good to use.".format(bold=color.BOLD, key=key['KeyId'], reset=color.END))
        else:
            print("KeyId: {} is NOT good to use.".format(key['KeyId']))


##############################################################################
def read_default_key():
    default_key = ''
    client = boto3.client('kms')
    response = client.list_keys(
        Limit=123
        # Marker='string'
    )
    for key in response['Keys']:
        key_description = client.describe_key(
            KeyId=key['KeyId']
            )
        if ('CUSTOMER' in key_description['KeyMetadata']['KeyManager'] and
                'Enabled' in key_description['KeyMetadata']['KeyState'] and
                'ENCRYPT_DECRYPT' in key_description['KeyMetadata']['KeyUsage']):
            default_key = key['KeyId']
            break
    return(default_key)


##############################################################################
def read_arguments():
    default_key = read_default_key()
    parser = argparse.ArgumentParser("Encrypt plaintext with KMS")
    parser.add_argument(
        "-p",
        "--plaintext",
        # required=True,
        help='Plaintext string to be encrypted'
    )
    parser.add_argument(
        "-k",
        "--key-id",
        default=default_key,
        help='KMS key id to use'
    )
    parser.add_argument(
        "-K",
        "--list-keys",
        action='store_true',
        help='List available keys in KMS'
    )
    args = parser.parse_args()

    if args.list_keys:
        list_kms_keys()
        sys.exit(0)

    if not args.plaintext:
        parser.error("Plaintext that needs encryption.")

    if not args.key_id:
        parser.error("Key to use to encrypt.")

    return args


##############################################################################
def main():
    # Init parser for command line args.
    pass_args = read_arguments()

    # Get the session to get the region name;
    session = boto3.session.Session()
    aws_region = session.region_name

    # create the kms client to do the decryption
    kms_client = boto3.client('kms')

    # KMS decrypt
    try:
        encrypted = kms_client.encrypt(
            KeyId=pass_args.key_id,
            Plaintext=pass_args.plaintext
        )
    except Exception as e:
        print(str(e))
        print("You are trying to decrypt in: {}".format(aws_region))
        print("Credentials expire at: {}".format(aws_creds_expiry()))
        sys.exit(1)

    # plaintext from the decrypted
    encrypted = base64.b64encode(encrypted['CiphertextBlob'])
    print("..................:: Encrypted with key: {} ::..................".format(pass_args.key_id))
    print(str(encrypted, 'utf-8'))
    print("..................................................................................................")


##############################################################################
if __name__ == '__main__':
    main()
