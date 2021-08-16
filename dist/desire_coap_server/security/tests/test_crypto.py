"""pyaiot crypto test module."""

from security.crypto import CryptoCtx

ALICE_ID = b'\xcc\xd1'
BOB_ID = b'\xac\xe2'
SALT = b'\xea\xea\xd4H\xe0V\xef\x83'
SECRET = b'\x16lE\xab\xb8\xd6\xdb\xe5\xd7q\xeb\x1d\x8b !\xa4'

PLAIN_TEXT_STRING = "a secret message"


def test_generate_keys_bob_alice_match():
    """Basic test, generated aes-ccm keys should match"""
    bob = CryptoCtx(BOB_ID, ALICE_ID)
    alice = CryptoCtx(ALICE_ID, BOB_ID)
    bob.generate_aes_ccm_keys(SALT, SECRET)
    alice.generate_aes_ccm_keys(SALT, SECRET)

    assert bob.common_iv == alice.common_iv
    assert bob.send_ctx_key == alice.recv_ctx_key
    assert alice.send_ctx_key == bob.recv_ctx_key


def test_crypto_encrypt_decrypt():
    """Test cose encryption decryption of a message"""
    bob = CryptoCtx(BOB_ID, ALICE_ID)
    alice = CryptoCtx(ALICE_ID, BOB_ID)
    bob.generate_aes_ccm_keys(SALT, SECRET)
    alice.generate_aes_ccm_keys(SALT, SECRET)
    encoded_msg = bob.encrypt(PLAIN_TEXT_STRING.encode('utf-8'))
    decoded_msg = alice.decrypt(encoded_msg)
    assert decoded_msg.decode('utf-8') == PLAIN_TEXT_STRING


def test_crypto_encrypt_decrypt_txt():
    """Test cose encryption decryption of a message"""
    bob = CryptoCtx(BOB_ID, ALICE_ID)
    alice = CryptoCtx(ALICE_ID, BOB_ID)
    bob.generate_aes_ccm_keys(SALT, SECRET)
    alice.generate_aes_ccm_keys(SALT, SECRET)
    encoded_msg = bob.encrypt_txt(PLAIN_TEXT_STRING)
    decoded_msg = alice.decrypt_txt(encoded_msg)
    assert decoded_msg == PLAIN_TEXT_STRING
