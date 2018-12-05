# coding: utf-8
import sys
sys.path.append('.')
from gen_keypair import *
import opcodes
import secp256k1

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

def create_raw(prev_hash, index, in_script, value, out_script):
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
        value = value.to_bytes(sizeof(value), 'little')
    elif not isinstance(value, bytes):
        raise Exception('value must be specified as int or bytes, not {}'.format(type(value)))
    if not isinstance(out_script, bytes):
        raise Exception('out_script must be specified as bytes')

    # check out the transaction structure at the head of this file for explanations
    tx = b'\x01\x00\x00\x00' # version
    tx += b'\x01' # input count
    print(tx)
    tx += prev_hash
    print(tx)
    tx += index
    script_length = len(in_script)
    tx += script_length.to_bytes(sizeof(script_length), 'big')
    tx += in_script
    tx += b'\xff\xff\xff\xff' # sequence
    tx += b'\x01' # output count
    tx += value
    script_length = len(out_script)
    tx += script_length.to_bytes(sizeof(script_length), 'big')
    tx += b'\x00\x00\x00\x00'

    return hex(int.from_bytes(tx, 'big'))


def deserialize(tx):
    """
    Deserializes a tx as a JSON object.

    :param tx: A raw tx.
    :return: A JSON.
    """
    version = tx[:4]
    print(version)
    input_count = tx[4]
    print(input_count)
    prev_hash = tx[5:37]
    print(prev_hash)
    index = tx[38]



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
                serialized += value.to_bytes(sizeof(value), 'big')
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
    return b'\x1e' + total_len.to_bytes(sizeof(total_len), 'big') + b'\x02' + r_len.to_bytes(sizeof(r_len), 'big') \
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

privkey = b"\x02\xac\x8f\xd3\x0e\x12\xf0\x1b0\x814\xc8\xb3\x11\xc6~\xbaX\xefd't\x81\x96\xfb\x9e\\\xb6\xb7\xa6\n\xa9"
(x, y) = secp256k1.privtopub(privkey)
pubkey = b'\x04' + x.to_bytes(sizeof(x), 'big') + y.to_bytes(sizeof(y), 'big')
prev_txid = 0xe79b8048c5660e5bf1891576f47a2bea4426fa22909a900dbefb99b41900869f
# Avant de la signer, le unlocking script (scriptsig) est rempli avec le locking script (scriptPubKey) de la precedente tx
scriptsig = parse_script('OP_DUP OP_HASH160 969be2220ff689cd3e05f0b4def5bf2359d90530 OP_EQUALVERIFY OP_CHECKSIG')
scriptpubkey = parse_script('OP_DUP OP_HASH160 969be2220ff689cd3e05f0b4def5bf2359d90530 OP_EQUALVERIFY OP_CHECKSIG')
tx = create_raw(prev_txid, 0, scriptsig, 100000000, scriptpubkey)[2:] # Pour eviter le 0x
tx = int(tx, 16) # To convert to bytes
sig = sign_tx(tx.to_bytes(sizeof(tx), 'big') + b'\x01\x00\x00\x00', privkey) # + hash code type
sig_hex = hex(int.from_bytes(sig + b'\x01', 'big'))[2:] # + hash code type (cette fois il fait que 1 byte)
pubkey_hex = hex(int.from_bytes(pubkey, 'big'))[2:]
scriptsig = parse_script(hex(len(sig + b'\x01'))[2:] + sig_hex + hex(len(pubkey))[2:] + pubkey_hex)
tx = create_raw(prev_txid, 0, scriptsig, 1, scriptpubkey)
print(tx)
deserialize(tx)