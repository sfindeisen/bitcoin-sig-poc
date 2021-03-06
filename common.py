import hashlib
import logging

import ecdsa
import bech32

# Supported Bech32 address types (human-readable prefixes).
# The first one is the default one.
BECH32_ADDRESS_TYPES = ["bc", "bcrt", "df"]

def make_bitcoin_message_hash(msg_s):
    # TODO: message must not be too long!
    data_bytes = ("\x18Bitcoin Signed Message:\x0A" + chr(len(msg_s)) + msg_s).encode('utf-8')
    logging.debug("make_bitcoin_message_hash: {} => {}".format(msg_s, data_bytes))
    data_hash  = hashlib.sha256(data_bytes).digest()
    logging.debug("make_bitcoin_message_hash: {} => {}".format(msg_s, data_hash.hex()))
    return data_hash

def check_ripemd160():
    """Checks if RIPEMD-160 cipher is available from the local OpenSSL implementation."""
    logging.debug("Available hashlib algorithms: {}".format(hashlib.algorithms_available))
    if "ripemd160" not in hashlib.algorithms_available:
        raise RuntimeError("RIPEMD-160 algorithm is not available in Python standard library (hashlib). Check your OpenSSL version and try again.")

def ripemd160(x_bytes):
    """Encodes given bytestring using RIPEMD-160."""
    hobj = hashlib.new('ripemd160')
    hobj.update(x_bytes)
    digest = hobj.digest()
    logging.debug("RIPEMD-160: {} => {}".format(x_bytes.hex(), digest.hex()))
    return digest

def validate_bech32(bech32_addr_s):
    for hrp in BECH32_ADDRESS_TYPES:
        if bech32_addr_s.startswith(hrp):
            return True
    return False

def pubkey_to_bech32(public_key, hrp):
    """Converts given public key to Bech32."""
    pk_compressed = public_key.to_string(encoding='compressed')
    logging.debug("pubkey_to_bech32: pk_compressed: {}".format(pk_compressed.hex()))
    pk_hash = ripemd160(hashlib.sha256(pk_compressed).digest())
    logging.debug("pubkey_to_bech32: pk_hash: {}".format(pk_hash.hex()))

    witness_version = 0
    b32 = bech32.encode(hrp, witness_version, pk_hash)
    logging.debug("pubkey_to_bech32: {}".format(b32))
    return b32
