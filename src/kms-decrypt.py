#!/usr/bin/env python3

import boto3
import base64
import argparse
import os
import sys
import time
temp_file_location = "/tmp/plaintext"


##############################################################################
def aws_creds_expiry():
    return time.strftime('%Y-%m-%d %a %H:%M:%S', time.localtime(int(os.environ['AWS_CREDS_EXPIRY'])))


##############################################################################
def write_to_file(plaintext):
    f = open(temp_file_location, 'w')
    f.write(str(plaintext, 'utf-8'))
    f.close()


##############################################################################
def read_arguments():

    parser = argparse.ArgumentParser("Decrypt KMS encrypted string")
    parser.add_argument(
        "-e",
        "--encrypted-string",
        required=True,
        help='KMS encrypted string that needs decrypting'
    )
    parser.add_argument(
        "-p",
        "--print-plaintext",
        action='store_true',
        default=False,
        help='Output decrypted string plaintext on the screen.'
    )
    args = parser.parse_args()

    if not args.encrypted_string:
        parser.error("I mean you need to pass something to encrypt")

    return args


##############################################################################
def main():

    command_line_args = read_arguments()

    # Get the session to get the region name;
    session = boto3.session.Session()
    aws_region = session.region_name

    # create the kms client to do the decrypttion
    kms_client = boto3.client('kms')

    # base64 decode into a cipher text blob
    blob = base64.b64decode(command_line_args.encrypted_string)

    # KMS decrypt
    try:
        aws_region = session.region_name
        decrypted = kms_client.decrypt(CiphertextBlob=blob)
    except Exception as e:
        print(str(e))
        print("You are trying to decrypt in: {}".format(aws_region))
        print("Credentials expire at: {}".format(aws_creds_expiry()))
        sys.exit(1)

    plaintext = decrypted['Plaintext']

    if command_line_args.print_plaintext:
        print(
            " Are you alone ? No body staring at your monitor ? OK to print plaintext ? [y or n]",
            end='->  ',
            flush=True
        )
        user_says = sys.stdin.readline().rstrip('\n')
        print("++++++++++++++++++++ Plain Text Alert +++++++++++++++++++++")
        if user_says == 'y':
            print(str(plaintext, 'utf-8'))
            print("You should definitely consult someone or may be print it on a t-shirt ")
        else:
            print("hmmmm good call. Written to " + temp_file_location)
            write_to_file(plaintext)
    else:
        # write plaintext to file.
        print("Writing plaintext to {}".format(temp_file_location))
        write_to_file(plaintext)

##############################################################################
if __name__ == '__main__':
    main()
