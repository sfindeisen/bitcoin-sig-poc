import hashlib
import logging

import ecdsa
import bech32

def check_ripemd160():
    # check for RIPEMD-160
    logging.debug("Available hashlib algorithms: {}".format(hashlib.algorithms_available))
    if "ripemd160" not in hashlib.algorithms_available:
        raise RuntimeError("RIPEMD-160 algorithm is not available in Python standard library (hashlib). Check your OpenSSL version and try again.")

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