#!/usr/bin/env python3

import argparse
import base64
import hashlib
import logging
import sys

import ecdsa
import bech32

def ripemd160(x_bytes):
    logging.debug("RIPEMD-160: {}".format(x_bytes))
    hobj = hashlib.new('ripemd160')
    hobj.update(x_bytes)
    digest = hobj.digest()
    logging.debug("RIPEMD-160: {} => {}".format(x_bytes, digest))
    return digest

def pubkey_to_bech32(public_key):
    pk_compressed = public_key.to_string(encoding='compressed')
    logging.debug("pubkey_to_bech32: pk_compressed: {}".format(pk_compressed))
    pk_hash = ripemd160(hashlib.sha256(pk_compressed).digest())
    logging.debug("pubkey_to_bech32: pk_hash: {}".format(pk_hash))

    for i in range(0,17):
        b32 = bech32.encode("bcrt", i, pk_hash)
        logging.debug("pubkey_to_bech32 LOOP: {}".format(b32))

    b32 = bech32.encode("bcrt", 0, pk_hash)
    logging.debug("pubkey_to_bech32: {}".format(b32))
    return b32

def verify(addr_s, data_bytes, sig_bytes):
    data_digest = hashlib.sha256(data_bytes).digest()
    logging.debug("verify: data_digest: {}".format(data_digest))

    # recover verifying keys
    verifying_keys = ecdsa.keys.VerifyingKey.from_public_key_recovery_with_digest(
        sig_bytes,
        data_digest,
        ecdsa.SECP256k1,
        hashfunc=hashlib.sha256,
        sigdecode=ecdsa.util.sigdecode_der
    )

    logging.debug("verify: from_public_key_recovery_with_digest: {}".format(verifying_keys))

    for vk in verifying_keys:
        if addr_s == pubkey_to_bech32(vk):
            return True

#    # verify the digest using at least 1 key
#    for vk in verifying_keys:
#        ver_digest = vk.verify_digest(
#            sig_bytes,
#            data_digest,
#            sigdecode=ecdsa.util.sigdecode_der
#        )
#
#        logging.debug("verify_digest: {} => {}".format(vk, ver_digest))
#        if ver_digest:
#            return True

    return False

if __name__ == '__main__':

    parser = argparse.ArgumentParser(
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
    logging.info("Available hashlib algorithms: {}".format(hashlib.algorithms_available))
    if "ripemd160" not in hashlib.algorithms_available:
        raise RuntimeError("RIPEMD-160 algorithm is not available in Python standard library (hashlib). Check your OpenSSL version and try again.")

    # encode input message as UTF-8 bytes
    data_bytes = args.message.encode('utf-8')
    # decode input signature from base64
    sig_bytes = base64.b64decode(args.sig, validate=True)

    # verify
    verify_result = verify(args.addr, data_bytes, sig_bytes)
    print("Signature verification OK!" if verify_result else "Signature verification error.")
