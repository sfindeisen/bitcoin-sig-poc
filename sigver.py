#!/usr/bin/env python3

import argparse
import base64
import hashlib
import logging
import sys

import ecdsa

def verify(data_bytes, sig_bytes):
    verifying_keys = ecdsa.keys.VerifyingKey.from_public_key_recovery(
        sig_bytes,
        data_bytes,
        ecdsa.SECP256k1,
        hashfunc=hashlib.sha256,
        sigdecode=ecdsa.util.sigdecode_der
    )

    logging.info("Recovered verifying keys: {}".format(verifying_keys))

if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        add_help=True, allow_abbrev=False, epilog="""This program comes with ABSOLUTELY NO WARRANTY.""")

    parser.add_argument("--verbose", required=False, action="store_true", default=False, help="verbose processing")
    parser.add_argument("--addr",    required=False, help="Bitcoin address")
    parser.add_argument("--message", required=True,  help="Message (plain ASCII)")
    parser.add_argument("--sig",     required=True,  help="signature (base64 encoded)")
    args = parser.parse_args()

    # Setup logging
    log_format = '{levelname:8} {threadName:<14} {message}'
    logging.basicConfig(stream=sys.stderr, level=(logging.DEBUG if args.verbose else logging.INFO), format=log_format, style='{')

    # encode input message as UTF-8 bytes
    data_bytes = args.message.encode('utf-8')
    # decode input signature from base64
    sig_bytes = base64.b64decode(args.sig, validate=True)
    # verify
    verify(data_bytes, sig_bytes)
