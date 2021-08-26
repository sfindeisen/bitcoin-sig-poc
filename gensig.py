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
    parser.add_argument("--bech32-hrp", required=False, choices=common.BECH32_ADDRESS_TYPES, default=common.BECH32_ADDRESS_TYPES[0], help="Bech32 address type (human-readable prefix)")
    parser.add_argument("--message",    required=True,  help="Message to sign (plain ASCII)")
    args = parser.parse_args()

    # Setup logging
    log_format = '{levelname:8} {threadName:<14} {message}'
    logging.basicConfig(stream=sys.stderr, level=(logging.DEBUG if args.verbose else logging.INFO), format=log_format, style='{')

    # check for RIPEMD-160
    common.check_ripemd160()

    # compute input message hash
    data_hash = common.make_bitcoin_message_hash(args.message)

    # generate the keys
    sigkey = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)
    verkey = sigkey.verifying_key

    # generate the signature
    sig = sigkey.sign_deterministic(data_hash, sigencode=ecdsa.util.sigencode_der)
    assert verkey.verify(sig, data_hash, sigdecode=ecdsa.util.sigdecode_der)
    logging.debug("signature: {}".format(sig))
    sig64 = base64.b64encode(sig).decode()

    # output results
    print("Public key : {}".format(common.pubkey_to_bech32(verkey, args.bech32_hrp)))
    print("Message    : {}".format(args.message))
    print("Signature  : {}".format(sig64))
