import hashlib
import os
import json
import platform
import subprocess


class ConfigManager:
    def __init__(self, config_file="config.json"):
        self.config_file = config_file
        self.defaults = {
            "encrypt_dir": os.path.abspath("data/encrypted"),
            "decrypt_dir": os.path.abspath("data/decrypted"),
            "theme": "Темная"
        }

    def load(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    return {**self.defaults, **json.load(f)}
            except Exception:
                return self.defaults
        return self.defaults

    def save(self, config_data):
        with open(self.config_file, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=4, ensure_ascii=False)


class FileSystem:
    @staticmethod
    def format_bytes(size):
        if size == 0:
            return "0 B"
        units, i = ("B", "KB", "MB", "GB"), 0
        while size >= 1024 and i < len(units) - 1:
            size /= 1024
            i += 1
        return f"{size:.2f} {units[i]}"

    @staticmethod
    def open_explorer(path):
        if not os.path.exists(path):
            os.makedirs(path, exist_ok=True)
        curr_os = platform.system()
        if curr_os == "Windows":
            os.startfile(path)
        elif curr_os == "Darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])


class Hasher:
    @staticmethod
    def hash_password(password, salt="static_salt_for_app"):
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt.encode(),
            100000
        ).hex()
