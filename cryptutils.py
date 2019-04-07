try:
    # windows
    from Cryptodome.Random.random import randint, getrandbits
    from Cryptodome.Random import get_random_bytes
    from Cryptodome.Cipher import DES3
except:
    # linux
    from Crypto.Random.random import randint, getrandbits
    from Crypto.Random import get_random_bytes
    from Crypto.Cipher import DES3

import MillerRabin
import arithmetic


def bytes_to_int(data):
    return int.from_bytes(data, 'big')


def int_to_bytes(data):
    return data.to_bytes((data.bit_length() + 7) // 8, 'big')


def des_encrypt(data, key):

    # align to 8 bytes
    data_len = len(data)
    if data_len % 8 != 0:
        data += b'\x03' * (8 - data_len % 8)

    cipher = DES3.new(key, DES3.MODE_ECB)
    return cipher.encrypt(data)


def des_decrypt(data, key):
    cipher = DES3.new(key, DES3.MODE_ECB)
    return cipher.decrypt(data)


def get_big_prime(bits):
    return MillerRabin.gen_prime(bits)


class MasseyOmuraProtocol:

    def __init__(self, prime):

        # generate parameters e, d
        # for enryption and decrypttion
        e, d = self.generate_keys(prime)

        # remember keys and prime
        self.prime = prime
        self.e = e
        self.d = d

    def encrypt_msg(self, msg):

        if msg > self.prime - 1:
            raise ValueError('Message is too long')

        return pow(msg, self.e, self.prime)

    def decrypt_msg(self, msg):
        return pow(msg, self.d, self.prime)

    @staticmethod
    def generate_keys(prime):
        """ generate random parameter e = [2..self.prime-1] which has d = e^-1 """

        while True:
            e = randint(2, prime - 2)
            if arithmetic.gcd(e, prime - 1) == 1:
                d = arithmetic.modInverse(e, prime - 1)
                break

        return e, d
