#!/usr/bin/env python3

import boto3
import base64
import argparse
import sys

temp_file_location = "/tmp/plaintext"


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
def error(msg):
    print("{bold}{red}[ERROR]{reset} {text}".format(bold=color.BOLD, red=color.RED, reset=color.END, text=msg))


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

    # create the kms client to do the decrypttion
    kms_client = boto3.client('kms')

    # base64 decode into a cipher text blob
    try:
        blob = base64.b64decode(command_line_args.encrypted_string)
    except Exception as e:
        error(str(e))
        print("Hmmm... It doesn't look good... Are you trying to decrypt undecryptable? ;-)")
        sys.exit(1)

    # KMS decrypt
    try:
        decrypted = kms_client.decrypt(CiphertextBlob=blob)
    except Exception as e:
        error(str(e))
        print("Are you logged in AWS? It doesn't look like... Check your credentials.")
        sys.exit(1)

    plaintext = decrypted['Plaintext']

    if command_line_args.print_plaintext:
        print(
            "\n Are you alone? No body staring at your monitor? OK to print plaintext ? [y or n]",
            end='->  ',
            flush=True
        )
        user_says = sys.stdin.readline().rstrip('\n')
        print("..............................:: PLAIN TEXT ::..............................")
        if user_says == 'y':
            print(str(plaintext, 'utf-8'))
            print("......................................................:: plague-doctor ::...")
            print("..:: You should definitely consult someone before print it on a t-shirt ::..")
        else:
            print("......................................................:: plague-doctor ::...")
            print("..::  hmmmm good call. Written to {}".format(temp_file_location))
            write_to_file(plaintext)
    else:
        # write plaintext to file.
        print("......................................................:: plague-doctor ::...")
        print("..::  hmmmm good call. Written to {}".format(temp_file_location))
        write_to_file(plaintext)


##############################################################################
if __name__ == '__main__':
    main()
