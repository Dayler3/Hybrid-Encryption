import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class KeyManager:
    def __init__(self, keys_dir="keys"):
        self.keys_dir = keys_dir
        os.makedirs(self.keys_dir, exist_ok=True)

    def generate_keys(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        with open(os.path.join(self.keys_dir, "private_key.pem"), "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open(os.path.join(self.keys_dir, "public_key.pem"), "wb") as f:
            f.write(private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    def load_private_key(self):
        with open(os.path.join(self.keys_dir, "private_key.pem"), "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    def load_public_key(self):
        with open(os.path.join(self.keys_dir, "public_key.pem"), "rb") as f:
            return serialization.load_pem_public_key(f.read())


class FileEncryptor:
    def encrypt_file(self, file_path, output_path, public_key):
        aes_key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        
        with open(file_path, 'rb') as f:
            data = f.read()
            
        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        enc_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        
        with open(output_path, 'wb') as f:
            f.write(len(enc_aes_key).to_bytes(4, 'big'))
            f.write(enc_aes_key)
            f.write(nonce)
            f.write(ciphertext)

    def decrypt_file(self, encrypted_path, output_path, private_key):
        with open(encrypted_path, 'rb') as f:
            key_len = int.from_bytes(f.read(4), 'big')
            enc_aes_key = f.read(key_len)
            nonce = f.read(12)
            ciphertext = f.read()

        aes_key = private_key.decrypt(
            enc_aes_key,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        
        aesgcm = AESGCM(aes_key)
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)

        with open(output_path, 'wb') as f:
            f.write(decrypted_data)