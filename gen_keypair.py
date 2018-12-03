# coding: utf-8
import os
import uuid
import time
import hashlib
from math import log


# From https://github.com/darosior/bitcoineasy/blob/master/bitcoineasy/utils.py
def sizeof(n):
    """
    get the size in bytes of an integer, https://stackoverflow.com/questions/14329794/get-size-of-integer-in-python

    :param n: the integer to get the size from
    :return: the size in bytes of the int passed as the first parameter.
    """
    if n == 0:
        return 1
    return int(log(n, 256)) + 1


def hash160(bytes, bin=False):
    """
    Returns the ripemd160(sha256(data)), used a lot in Bitcoin.

    :param bin: If set to true, returns bytes.
    """
    rip = new('ripemd160')
    rip.update(sha256(bytes).digest())
    if bin:
        return rip.digest()  # type : bytes
    else:
        return rip.hexdigest()  # type : str


def double_sha256(bytes, bin=False):
    """
    Returns the sha256(sha256(data)), used a lot in Bitcoin.

    :param bin: If set to true, returns bytes.
    """
    h = sha256(bytes)
    if bin:
        return sha256(h.digest()).digest()  # type : bytes
    else:
        return sha256(h.digest()).hexdigest()  # type : str


def gen_random():
    """
    Generates a random number from a CSRNG.
    """
    seconds = int(time.time())
    entrop1 = double_sha256(seconds.to_bytes(util.base58.sizeof(seconds), 'big'))
    entrop2 = double_sha256(os.urandom(256))
    entrop3 = double_sha256(uuid.uuid4().bytes)
    entropy = double_sha256(entrop1 + entrop2 + entrop3)
    return int.from_bytes(entropy, 'big')


def b58encode(payload):
    """
    Takes a number (int or bytes) and returns its base58_encoding.

    :param payload: The data to encode, can be bytes or int
    :return: the number passed as first parameter as a base58 encoded str.
    """
    if isinstance(payload, bytes):
        n = int.from_bytes(payload, 'big')
    elif isinstance(payload, int):
        n = payload
    else:
        raise ValueError('b58encode takes bytes or int')

    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    x = n % 58
    rest = n // 58
    if rest == 0:
        return alphabet[x]
    else:
        return b58encode(rest) + alphabet[x]


def b58decode(string):
    """Takes a base58-encoded number and returns it in base10.
    :param string: the number to base58_decode (as str).
    :return: the number passed as first parameter, base10 encoded.
    """
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    # Populating a dictionary with base58 symbol chart
    dict = {}
    k = 0
    for i in alphabet:
        dict[i] = k
        k += 1
    n = 0  # Result
    pos = 0  # Cf https://www.dcode.fr/conversion-base-n
    for i in string:
        for y in alphabet:
            if i == y:
                n = n * 58 + dict[i]
        pos += 1
    return n


def encode_check(payload):
    """Returns the base58 encoding with a 4-byte checksum.

    :param payload: The data (as bytes) to encode.
    """
    checksum = sha256d(payload)[:4]
    if payload[0] == 0x00:
        # Again, the leading 0 problem which results in nothing during int conversion
        return b58encode(b'\x00') + b58encode(payload + checksum)
    else:
        return b58encode(payload + checksum)


def decode_check(string):
    """Returns the base58 decoded value, verifying the checksum.

    :param string: The data to decode, as a string.
    """
    number = b58decode(string)
    # Converting to bytes in order to verify the checksum
    payload = number.to_bytes(sizeof(number), 'big')
    if payload and sha256d(payload[:-4])[:4] == payload[-4:]:
        return payload[:-4]
    else:
        return None


def wif_encode(data):
    """
    WIF-encode the data (which would likely be a Bitcoin private key) provided.

    :param data: The bytes to WIF-encode.
    """
    return base58check_encode(data, 0x80.to_bytes(1, 'big')) # str


def wif_decode(string):
    """
    WIF-decode the provided string (which would likely be a WIF-encoded Bitcoin private key).
    """
    dec = base58check_decode(string)
    compressed = string[0] == 'K' or string[0] == 'L'
    if compressed:
        return dec[:len(dec) - 1] # bytes
    else:
        return dec # bytes