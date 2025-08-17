import os
import struct
from Crypto.Cipher import AES

class Encryption:
    @staticmethod
    def aes_encrypt(session_key: bytes, plain_text: bytes, random_nonce):
        cipher = AES.new(session_key, AES.MODE_GCM, nonce=random_nonce)
        cipher_text, tag = cipher.encrypt_and_digest(plain_text)
        encrypted_data = cipher_text + tag
        return encrypted_data

    @staticmethod
    def aes_decrypt(session_key: bytes, cipher_text: bytes, random_nonce):
        cipher = AES.new(session_key, AES.MODE_GCM, nonce=random_nonce)
        decrypted_data = cipher.decrypt_and_verify(cipher_text[:-16], cipher_text[-16:])
        return decrypted_data

    @staticmethod
    def encrypt(session_key, plain_text):
        random_nonce = os.urandom(12)

        encrypted_data = Encryption.aes_encrypt(session_key, plain_text, random_nonce)

        cipher_text, tag = encrypted_data[:-16], encrypted_data[-16:]

        packet = struct.pack(f'!12sI{len(cipher_text)}s16s', random_nonce, len(cipher_text), cipher_text, tag)
        return packet

    @staticmethod
    def decrypt(session_key, packet):
        nonce, cipher_text_length = struct.unpack('!12sI', packet[:16])
        cipher_text, tag = struct.unpack(f'!{cipher_text_length}s16s', packet[16:])

        combined_ciphertext = cipher_text + tag

        decrypted_data = Encryption.aes_decrypt(session_key, combined_ciphertext, nonce)
        return decrypted_data.decode('utf-8')
