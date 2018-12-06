# coding: utf-8
import sys
sys.path.append('.')
from gen_keypair import *
import opcodes
import secp256k1
import binascii

"""
====Transaction structure====
version : 4 bytes
input_count : varint
inputs
    previous output hash : 32 bytes
    index : 4 bytes
    scriptLength: varint
    script : scriptLength bytes
    sequence : 4 bytes
output_count : varint
    value : 8 bytes
    scriptLength : varint
    script: scriptLength bytes
txlocktime : 4 bytes
==============================
"""

"""
To keep it simple, we'll use just a single output and a single input
"""

def serialize(prev_hash, index, in_script, value, out_script):
    """
    Creates a serialized transaction from given values.

    :param prev_hash: the hash of the previous transaction from which we take the input. (int or bytes)
    :param index: the place of the output in the 'output list'. (int or bytes)
    :param in_script: the input script (unlocking prev tx locking script), as bytes.
    :param value: the amount in satoshis to spend from the output. (int or bytes)
    :param out_script: the output script (locking coins spent)

    :return: an hex-encoded serialized tx.
    """
    # We then check every parameters in order to avoid errors when submitting the tx to the network
    if isinstance(prev_hash, int):
        prev_hash = prev_hash.to_bytes(sizeof(prev_hash), 'big')
    elif not isinstance(prev_hash, bytes):
        raise Exception('prev_hash must be specified as int or bytes, not {}'.format(type(prev_hash)))
    if isinstance(index, int):
        index = index.to_bytes(4, 'little',)
    elif not isinstance(index, bytes):
        raise Exception('index must be specified as int or bytes, not {}'.format(type(index)))
    if not isinstance(in_script, bytes):
        raise Exception('in_script must be specified as bytes')
    if isinstance(value, int):
        value = value.to_bytes(8, 'little')
    elif not isinstance(value, bytes):
        raise Exception('value must be specified as int or bytes, not {}'.format(type(value)))
    if not isinstance(out_script, bytes):
        raise Exception('out_script must be specified as bytes')

    # check out the transaction structure at the head of this file for explanations
    tx = b'\x01\x00\x00\x00' # version
    tx += b'\x01' # input count
    tx += prev_hash[::-1]
    tx += index
    script_length = len(in_script)
    tx += script_length.to_bytes(sizeof(script_length), 'big')
    tx += in_script
    tx += b'\xff\xff\xff\xff' # sequence
    tx += b'\x01' # output count
    tx += value
    script_length = len(out_script)
    tx += script_length.to_bytes(sizeof(script_length), 'big')
    tx += out_script
    tx += b'\x00\x00\x00\x00' # timelock

    return binascii.hexlify(tx)


def decode_print(tx):
    """
    Displays a deserialized tx (JSON-like).

    :param tx: A raw tx.
    """
    print('{')
    print(' version : ', binascii.hexlify(tx[:4]), ',')
    print(' input_count : ', tx[4], ',')
    print(' prev_hash : ', binascii.hexlify(tx[5:37]), ',')
    print(' index : ', binascii.hexlify(tx[37:41]), ',')
    scriptsig_len = tx[41]
    print(' scriptsig_len : ', scriptsig_len, ',')
    print(' scriptsig : ', binascii.hexlify(tx[42:42+scriptsig_len]), ',')
    print(' sequence', binascii.hexlify(tx[42+scriptsig_len:42+scriptsig_len+4]), ',')
    print(' output_count', tx[42+scriptsig_len+4], ',')
    print(' value : ', binascii.hexlify(tx[42+scriptsig_len+4:42+scriptsig_len+12]), ',') # aie aie aie
    output_length = tx[42+scriptsig_len+13]
    print(' output_length : ', output_length, ',')
    print(' output : ', binascii.hexlify(tx[42+scriptsig_len+14:42+scriptsig_len+13+output_length+1]), ',') # ouie
    print(' locktime : ', binascii.hexlify(tx[42+scriptsig_len+13+output_length+1:42+scriptsig_len+output_length+18]), ',')
    print('}')


def parse_script(script):
    """
    Parses and serializes a script.

    :param script: The script to serialize, as string.
    :return: The serialized script, as bytes.
    """
    # Parsing the string
    instructions = script.split(' ')
    serialized = b''
    for i in instructions:
        if i in opcodes.OPCODE_NAMES :
            op = opcodes.OPCODE_NAMES.index(i)
            serialized += op.to_bytes(sizeof(op), 'big')
        else:
            try:
                value = int(i, 16)
                length = sizeof(value)
                serialized += length.to_bytes(sizeof(length), 'big') + value.to_bytes(sizeof(value), 'big')
            except:
                raise Exception('Unexpected instruction in script : {}'.format(i))
    if len(serialized) > 10000:
        raise Exception('Serialized script should be less than 10,000 bytes long')
    return serialized

def der_encode(r, s):
    """
    DER-encodes a signed tx. https://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always-65-13232-bytes-long
    """
    r_len = sizeof(r)
    s_len = sizeof(s)
    total_len = (4 + r_len + s_len)
    return b'\x30' + total_len.to_bytes(sizeof(total_len), 'big') + b'\x02' + r_len.to_bytes(sizeof(r_len), 'big') \
            + r.to_bytes(sizeof(r), 'big') + s_len.to_bytes(sizeof(s_len), 'big') + s.to_bytes(sizeof(s), 'big')

def sign_tx(tx, key):
    """
    Signs a raw transaction with the corresponding private key.

    :param tx: Serialized (INSA/Bit)coin transaction.
    :param key: (INSA/Bit)coin private key, as bytes.
    :return: Signed serialized (Bit/INSA)coin transaction.
    """
    tx_hash = double_sha256(tx, True)
    v, r, s = secp256k1.ecdsa_raw_sign(tx_hash, key)
    sig = der_encode(r, s) + b'\x01' # hash code
    return sig


def create_raw(privkey, prev_hash, index, in_script, value, out_script):
    """
    Creates a signed raw transaction

    :param privkey: bytes
    """
    pubkey = get_pubkey(privkey)
    in_script_len = len(in_script)
    in_script = in_script_len.to_bytes(sizeof(in_script_len), 'big') + in_script
    tx = serialize(prev_hash, index, in_script, value, scriptpubkey)
    sig = sign_tx(binascii.unhexlify(tx) + b'\x01\x00\x00\x00', privkey) # + hash code type
    sig_len = len(sig)
    pub_len = len(pubkey)
    scriptsig = sig_len.to_bytes(sizeof(sig_len), 'big') + sig + pub_len.to_bytes(sizeof(pub_len), 'big') + pubkey
    print(binascii.hexlify(scriptsig))
    return serialize(prev_hash, index, scriptsig, value, out_script)


privkey = b'\xce\xd1 `\xf6\x84\xb0\x88\xab\xd32\x19\x0b\x10\rr \xf67h\x16/f\xb5\x9b\xd0\x01\x1e\xd8\xa5>\xf4\x01'
prev_txid = 0x6632ae48ecfc5124e52db30103f79746adb5c0b163cbb4f11b45b780497d3cdb
# Avant de la signer, le unlocking script (scriptsig) est rempli avec le locking script (scriptPubKey) de la precedente tx
scriptsig = parse_script('OP_DUP OP_HASH160 a86c52f90b0e2ae853d8e9ea4403a4b68de7a7e0 OP_EQUALVERIFY OP_CHECKSIG')
scriptpubkey = parse_script('OP_DUP OP_HASH160 a86c52f90b0e2ae853d8e9ea4403a4b68de7a7e0 OP_EQUALVERIFY OP_CHECKSIG')

tx = create_raw(privkey, prev_txid, 0, scriptsig, 99000000, scriptpubkey)
print(tx)
decode_print(binascii.unhexlify(tx))