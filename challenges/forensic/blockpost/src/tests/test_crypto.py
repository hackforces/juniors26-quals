import random
import unittest

from mc_blockpost.crypto import (
    CFB8, aes128_encrypt_block, generate_rsa, minecraft_server_hash, rsa_parse_public_der,
    rsa_pkcs1v15_decrypt, rsa_pkcs1v15_encrypt, rsa_public_der,
)


class AesTest(unittest.TestCase):
    def test_fips197(self):
        key = bytes(range(16))
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.assertEqual(aes128_encrypt_block(key, pt).hex(), "69c4e0d86a7b0430d8cdb78070b4c55a")

    def test_cfb8_nist_sp800_38a(self):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes(range(16))
        pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d")
        ct = bytes.fromhex("3b79424c9c0dd436bace9e0ed4586a4f32b9")
        for pure in (True, False):
            with self.subTest(pure=pure):
                self.assertEqual(CFB8(key, iv, pure=pure).update(pt), ct)
                self.assertEqual(CFB8(key, iv, decrypt=True, pure=pure).update(ct), pt)

    def test_cfb8_is_a_continuous_stream(self):
        key = bytes(range(16, 32))
        data = bytes(random.Random(1).randrange(256) for _ in range(300))
        whole = CFB8(key, pure=True).update(data)
        c = CFB8(key, pure=True)
        self.assertEqual(c.update(data[:7]) + c.update(data[7:150]) + c.update(data[150:]), whole)
        self.assertEqual(CFB8(key).update(data), whole)    # key = IV по умолчанию


class RsaTest(unittest.TestCase):
    def test_keygen_deterministic(self):
        self.assertEqual(generate_rsa(1024, seed=5), generate_rsa(1024, seed=5))
        self.assertNotEqual(generate_rsa(1024, seed=5), generate_rsa(1024, seed=6))

    def test_der_and_pkcs1(self):
        n, e, d = generate_rsa(1024, seed=7)
        der = rsa_public_der(n, e)
        self.assertEqual(len(der), 162)                     # SPKI RSA-1024
        self.assertEqual(rsa_parse_public_der(der), (n, e))
        secret = bytes(range(16))
        ct = rsa_pkcs1v15_encrypt(n, e, secret, random.Random(1))
        self.assertEqual(len(ct), 128)
        self.assertEqual(rsa_pkcs1v15_decrypt(n, d, ct), secret)

    def test_server_hash_wiki_examples(self):
        self.assertEqual(minecraft_server_hash(b"Notch", b"", b""),
                         "4ed1f46bbe04bc756bcb17c0c7ce3e4632f06a48")
        self.assertEqual(minecraft_server_hash(b"jeb_", b"", b""),
                         "-7c9d5b0044c130109a5d7b5fb5c317c02b4e28c1")
        self.assertEqual(minecraft_server_hash(b"simon", b"", b""),
                         "88e16a1019277b15d58faf0541e11910eb756f6")


if __name__ == "__main__":
    unittest.main()
