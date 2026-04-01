import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class KeyManager:

    def __init__(self, keys_dir="keys"):
        self.keys_dir = keys_dir
        os.makedirs(self.keys_dir, exist_ok=True)

    def generate_keys(self, password=None):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        encryption = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
        with open(os.path.join(self.keys_dir, "private_key.pem"), "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption
            ))
        with open(os.path.join(self.keys_dir, "public_key.pem"), "wb") as f:
            f.write(private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    def load_private_key(self, password=None):
        with open(os.path.join(self.keys_dir, "private_key.pem"), "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=password.encode() if password else None)

    def load_public_key(self):
        with open(os.path.join(self.keys_dir, "public_key.pem"), "rb") as f:
            return serialization.load_pem_public_key(f.read())


class FileEncryptor:
    CHUNK_SIZE = 4 * 1024 * 1024

    def encrypt_file(self, file_path, output_path, public_key, progress_cb=None, stop_check=None):
        f_size = os.path.getsize(file_path)
        b_proc = 0
        last_ui_update = 0
        aes_key = os.urandom(32)
        nonce = os.urandom(16)
        enc_aes_key = public_key.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce))
        encryptor = cipher.encryptor()
        with open(file_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            f_out.write(len(enc_aes_key).to_bytes(4, 'big'))
            f_out.write(enc_aes_key)
            f_out.write(nonce)
            while chunk := f_in.read(self.CHUNK_SIZE):
                if stop_check and stop_check():
                    return False
                f_out.write(encryptor.update(chunk))
                b_proc += len(chunk)
                curr_prog = b_proc / f_size
                if progress_cb and (curr_prog - last_ui_update >= 0.01 or b_proc == f_size):
                    progress_cb(curr_prog)
                    last_ui_update = curr_prog
            f_out.write(encryptor.finalize())
        return True

    def decrypt_file(self, encrypted_path, output_path, private_key, progress_cb=None, stop_check=None):
        f_size = os.path.getsize(encrypted_path)
        b_proc = 0
        last_ui_update = 0
        with open(encrypted_path, 'rb') as f_in:
            k_len = int.from_bytes(f_in.read(4), 'big')
            enc_aes_key = f_in.read(k_len)
            nonce = f_in.read(16)
            b_proc += (4 + k_len + 16)
            aes_key = private_key.decrypt(enc_aes_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce))
            decryptor = cipher.decryptor()
            with open(output_path, 'wb') as f_out:
                while chunk := f_in.read(self.CHUNK_SIZE):
                    if stop_check and stop_check():
                        return False
                    f_out.write(decryptor.update(chunk))
                    b_proc += len(chunk)
                    curr_prog = b_proc / f_size
                    if progress_cb and (curr_prog - last_ui_update >= 0.01 or b_proc == f_size):
                        progress_cb(curr_prog)
                        last_ui_update = curr_prog
                f_out.write(decryptor.finalize())
        return True
