#!/usr/bin/env python3

import argparse
import base64
import hashlib
import logging
import sys

import ecdsa

import common

def verify(bech32_addr_s, data_bytes, sig_bytes):
    """Recovers the public key(s) from the signature and matches them against the given Bech32 address."""
    data_digest = hashlib.sha256(data_bytes).digest()
    logging.debug("verify: data_digest: {}".format(data_digest.hex()))

    # recover verifying keys
    verifying_keys = ecdsa.keys.VerifyingKey.from_public_key_recovery_with_digest(
        sig_bytes,
        data_digest,
        ecdsa.SECP256k1,
        hashfunc=hashlib.sha256,
        sigdecode=ecdsa.util.sigdecode_der
    )

    logging.debug("verify: from_public_key_recovery_with_digest: {}".format(verifying_keys))

    # We could now verify the digest with any of the keys, like this:
    #
    #     ver_digest = ver_key.verify_digest(
    #       sig_bytes,
    #       data_digest,
    #       sigdecode=ecdsa.util.sigdecode_der
    #     )
    #
    # This is not necessary because it always works (with each key).

    # Let's check if any of the keys matches the input address.
    # TODO: it would probably be faster to parse the input address type and just use that one.
    for vk in verifying_keys:
        for at in common.BECH32_ADDRESS_TYPES:
            if bech32_addr_s == common.pubkey_to_bech32(vk, at):
                return True

    return False

if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        description="Given an address, a message and a signature, extracts the public key and verifies the signature.",
        add_help=True, allow_abbrev=False, epilog="""This program comes with ABSOLUTELY NO WARRANTY.""")

    parser.add_argument("--verbose", required=False, action="store_true", default=False, help="verbose processing")
    parser.add_argument("--addr",    required=True,  help="Bitcoin address")
    parser.add_argument("--message", required=True,  help="Message (plain ASCII)")
    parser.add_argument("--sig",     required=True,  help="signature (base64 encoded)")
    args = parser.parse_args()

    # Setup logging
    log_format = '{levelname:8} {threadName:<14} {message}'
    logging.basicConfig(stream=sys.stderr, level=(logging.DEBUG if args.verbose else logging.INFO), format=log_format, style='{')

    # check for RIPEMD-160
    common.check_ripemd160()
    # encode input message as bytes
    data_bytes = common.make_bitcoin_message(args.message)
    # decode input signature from base64
    sig_bytes = base64.b64decode(args.sig, validate=True)
    logging.debug("sig_bytes: {}".format(sig_bytes.hex()))

    # verify
    verify_result = verify(args.addr, data_bytes, sig_bytes)
    print("Signature verification OK!" if verify_result else "Signature verification error.")
