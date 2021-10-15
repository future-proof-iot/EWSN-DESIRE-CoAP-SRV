"""pyaiot message encryption module"""

from typing import ByteString

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cose import headers
from cose.messages import Enc0Message
from cose.messages import CoseMessage
from cose.algorithms import AESCCM1664128
from cose.keys.keyparam import KpKid, KpAlg
from cose.keys import SymmetricKey


def bxor(ba1: ByteString, ba2: ByteString) -> ByteString:
    """XOR two byte strings"""
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


class CryptoCtx:
    NONCE_LENGTH = 13
    COMMON_IV_LENGTH = 13
    AES_CCM_KEY_LENGTH = 16  # 128 bits
    AES_CCM_TAG_LENGTH_BYTES = 8  # 64bits
    CTX_ID_MAX_LEN = 6

    def __init__(self, send_ctx_id: ByteString, recv_ctx_id: ByteString):
        self.send_ctx_key = None
        self.recv_ctx_key = None
        self.common_iv = None
        self.seq_nr = 0
        self.send_ctx_id = send_ctx_id
        self.recv_ctx_id = recv_ctx_id

    @staticmethod
    def __aes_ccm_key(
        salt: ByteString,
        secret: ByteString,
        info: ByteString,
        length: int = AES_CCM_KEY_LENGTH,
    ) -> ByteString:
        hkdf = HKDF(algorithm=hashes.SHA256(), salt=salt, info=info, length=length)
        key = hkdf.derive(secret)
        hkdf = HKDF(algorithm=hashes.SHA256(), salt=salt, info=info, length=length)
        hkdf.verify(secret, key)
        return key

    def gen_nonce(self, ctx_id: ByteString) -> ByteString:
        """Generates a nonce for a specific context id, sequence number
        is incremented after generating the nonce"""
        pad_seq_nr = list(self.seq_nr.to_bytes(5, byteorder="big"))
        pad_ctx_id = (self.NONCE_LENGTH - 5 - len(ctx_id)) * [0] + list(ctx_id)
        partial_iv = bytes(pad_ctx_id + pad_seq_nr)
        self.seq_nr += 1
        return bxor(self.common_iv, partial_iv)

    def generate_aes_ccm_keys(self, salt: ByteString, secret: ByteString) -> None:
        """Generates recv_ctx_key, send_ctx_key and common_iv from"""
        self.recv_ctx_key = CryptoCtx.__aes_ccm_key(salt, secret, self.recv_ctx_id)
        self.send_ctx_key = CryptoCtx.__aes_ccm_key(salt, secret, self.send_ctx_id)
        self.common_iv = CryptoCtx.__aes_ccm_key(
            salt, secret, b"", length=self.COMMON_IV_LENGTH
        )

    def decrypt(self, msg: ByteString) -> ByteString:
        """Returns a decoded COSE Encrypt0 message"""
        cose_msg = CoseMessage.decode(msg)
        cose_key = SymmetricKey(
            self.recv_ctx_key,
            optional_params={KpKid: self.recv_ctx_id, KpAlg: AESCCM1664128},
        )
        cose_msg.key = cose_key
        return cose_msg.decrypt()

    def encrypt(self, msg: ByteString) -> ByteString:
        """Returns a CBOR-encoded COSE Encrypt0 message"""
        msg = Enc0Message(
            phdr={headers.Algorithm: AESCCM1664128},
            uhdr={headers.IV: self.gen_nonce(self.send_ctx_id)},
            payload=msg,
        )
        cose_key = SymmetricKey(
            self.send_ctx_key,
            optional_params={KpKid: self.send_ctx_id, KpAlg: AESCCM1664128},
        )
        msg.key = cose_key
        return msg.encode()

    def decrypt_txt(self, msg: ByteString) -> str:
        """Returns a decoded COSE Encrypt0 message string"""
        return self.decrypt(msg).decode("ascii")

    def encrypt_txt(self, msg: str) -> ByteString:
        """Returns a CBOR-encoded COSE Encrypt0 message"""
        return self.encrypt(msg.encode("ascii"))
