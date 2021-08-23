#!/usr/bin/env python3

import argparse
import base64
import hashlib
import logging
import sys

import ecdsa

import common

if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        description="Given a message, generates a random address and the signature.",
        add_help=True, allow_abbrev=False, epilog="""This program comes with ABSOLUTELY NO WARRANTY.""")

    parser.add_argument("--verbose",    required=False, action="store_true", default=False, help="verbose processing")
    parser.add_argument("--bech32-hrp", required=False, choices=["bc", "bcrt"], default="xx", help="Bech32 address type (human-readable prefix)")
    parser.add_argument("--message",    required=True,  help="Message to sign (plain ASCII)")
    args = parser.parse_args()

    # Setup logging
    log_format = '{levelname:8} {threadName:<14} {message}'
    logging.basicConfig(stream=sys.stderr, level=(logging.DEBUG if args.verbose else logging.INFO), format=log_format, style='{')

    # check for RIPEMD-160
    common.check_ripemd160()

    # encode input message as UTF-8 bytes
    data_bytes = args.message.encode('utf-8')

    # generate the keys
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)
    vk = sk.verifying_key
    # generate the signature
    signature = sk.sign_deterministic(data_bytes, sigencode=ecdsa.util.sigencode_der)
    assert vk.verify(signature, data_bytes, sigdecode=ecdsa.util.sigdecode_der)
    logging.debug("signature: {}".format(signature))

    print("Signature (DER format, Base64 encoded): {}".format(base64.b64encode(signature)))
