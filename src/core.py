import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag


class KeyManager:
    def __init__(self, keys_dir="keys"):
        self.keys_dir = keys_dir
        os.makedirs(self.keys_dir, exist_ok=True)

    def generate_keys(self, password=None):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        enc = (serialization.BestAvailableEncryption(password.encode())
               if password else serialization.NoEncryption())
        with open(os.path.join(self.keys_dir, "private_key.pem"), "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=enc))
        with open(os.path.join(self.keys_dir, "public_key.pem"), "wb") as f:
            f.write(private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo))

    def load_private_key(self, password=None):
        with open(os.path.join(self.keys_dir, "private_key.pem"), "rb") as f:
            return serialization.load_pem_private_key(
                f.read(), password=password.encode() if password else None)

    def load_public_key(self):
        with open(os.path.join(self.keys_dir, "public_key.pem"), "rb") as f:
            return serialization.load_pem_public_key(f.read())


class FileEncryptor:
    CHUNK_SIZE = 4 * 1024 * 1024

    def encrypt_file(self, file_path, output_path, public_key, progress_cb=None, stop_check=None):
        f_size, b_proc = os.path.getsize(file_path), 0
        aes_key, nonce = os.urandom(32), os.urandom(12)
        enc_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(nonce)).encryptor()
        with open(file_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            f_out.write(len(enc_aes_key).to_bytes(4, 'big'))
            f_out.write(enc_aes_key)
            f_out.write(nonce)
            while chunk := f_in.read(self.CHUNK_SIZE):
                if stop_check and stop_check():
                    return False
                f_out.write(encryptor.update(chunk))
                b_proc += len(chunk)
                if progress_cb:
                    progress_cb(b_proc / f_size)
            encryptor.finalize()
            f_out.write(encryptor.tag)
        return True

    def decrypt_file(self, encrypted_path, output_path, private_key, progress_cb=None, stop_check=None):
        f_size = os.path.getsize(encrypted_path)
        with open(encrypted_path, 'rb') as f_in:
            raw_len = f_in.read(4)
            if not raw_len:
                raise ValueError("Файл пуст")
            k_len = int.from_bytes(raw_len, 'big')
            enc_aes_key, nonce = f_in.read(k_len), f_in.read(12)
            if len(enc_aes_key) != private_key.key_size // 8:
                raise ValueError("Неверная длина ключа")
            h_size = 4 + k_len + 12
            d_len = f_size - h_size - 16
            f_in.seek(-16, os.SEEK_END)
            tag = f_in.read(16)
            f_in.seek(h_size)
            aes_key = private_key.decrypt(
                enc_aes_key,
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            decryptor, b_proc = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag)).decryptor(), 0
            with open(output_path, 'wb') as f_out:
                try:
                    while b_proc < d_len:
                        if stop_check and stop_check():
                            return False
                        chunk = f_in.read(min(self.CHUNK_SIZE, d_len - b_proc))
                        if not chunk:
                            break
                        f_out.write(decryptor.update(chunk))
                        b_proc += len(chunk)
                        if progress_cb:
                            progress_cb(b_proc / d_len)
                    decryptor.finalize()
                except (InvalidTag, Exception):
                    if os.path.exists(output_path):
                        os.remove(output_path)
                    raise ValueError("Ошибка целостности или неверный ключ")
        return True
