import hashlib
import os
import json
import platform
import subprocess


class ConfigManager:
    def __init__(self, config_file="config.json"):
        self.config_file = config_file
        self.default_config = {
            "encrypt_dir": os.path.abspath("data/encrypted"),
            "decrypt_dir": os.path.abspath("data/decrypted"),
            "theme": "Темная"
        }

    def load(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    return {**self.default_config, **json.load(f)}
            except: 
                return self.default_config
        return self.default_config

    def save(self, config_data):
        with open(self.config_file, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=4, ensure_ascii=False)


class FileSystem:

    @staticmethod
    def format_bytes(size_bytes):
        if size_bytes == 0: return "0 B"
        units = ("B", "KB", "MB", "GB")
        i = 0
        while size_bytes >= 1024 and i < len(units) - 1:
            size_bytes /= 1024
            i += 1
        return f"{size_bytes:.2f} {units[i]}"

    @staticmethod
    def get_formatted_size(path):
        try:
            return FileSystem.format_bytes(os.path.getsize(path))
        except: 
            return "0 B"

    @staticmethod
    def open_explorer(path):
        if not os.path.exists(path): 
            os.makedirs(path, exist_ok=True)
            
        if platform.system() == "Windows":
            os.startfile(path)
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])


class Hasher:
    @staticmethod
    def get_file_hash(file_path):
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except: 
            return "Ошибка хеша"