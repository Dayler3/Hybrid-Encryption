import os
from src.core import FileEncryptor

class CryptoProcessor:
    def __init__(self, key_manager):
        self.encryptor = FileEncryptor()
        self.km = key_manager

    def run(self, files, mode, output_dir, on_progress, on_log):
        success_count = 0
        total = len(files)
        
        for i, path in enumerate(files, 1):
            try:
                if mode == "encrypt":
                    out = os.path.join(output_dir, os.path.basename(path) + ".enc")
                    self.encryptor.encrypt_file(path, out, self.km.load_public_key())
                else:
                    if not path.endswith(".enc"): 
                        on_log(f"Пропуск: {os.path.basename(path)} (не .enc)")
                        continue
                    
                    out = os.path.join(output_dir, "restored_" + os.path.basename(path)[:-4])
                    self.encryptor.decrypt_file(path, out, self.km.load_private_key())
                
                success_count += 1
                on_log(f"[{i}/{total}] OK: {os.path.basename(path)}")
                
            except Exception as e:
                on_log(f"ОШИБКА в {os.path.basename(path)}: {e}")

            on_progress(i / total)
            
        return success_count, total