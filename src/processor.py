import os
import threading
import time
from src.core import FileEncryptor


class CryptoProcessor:
    def __init__(self, key_manager):
        self.km = key_manager
        self.encryptor = FileEncryptor()
        self.stop_signal = False

    def stop(self):
        self.stop_signal = True

    def run_async(self, files, mode, out_dir, progress_cb, log_cb, finish_cb, password=None):
        self.stop_signal = False
        thread = threading.Thread(
            target=self._process_task,
            args=(files, mode, out_dir, progress_cb, log_cb, finish_cb, password)
        )
        thread.daemon = True
        thread.start()

    def _process_task(self, files, mode, out_dir, progress_cb, log_cb, finish_cb, password):
        total_files = len(files)
        success = 0
        start_time = time.time()
        try:
            key = self.km.load_public_key() if mode == "encrypt" else self.km.load_private_key(password)
            for i, f_path in enumerate(files):
                if self.stop_signal:
                    break
                name = os.path.basename(f_path)
                f_size = os.path.getsize(f_path)
                f_start_time = time.time()
                try:
                    if mode == "encrypt":
                        out_name = name + ".enc"
                    else:
                        name.replace(".enc", "")
                    out_path = os.path.join(out_dir, out_name)

                    def update_ui(f_percent):
                        overall = (i / total_files) + (f_percent / total_files)
                        elapsed = time.time() - f_start_time
                        if elapsed > 0 and f_percent > 0:
                            speed = (f_size * f_percent) / elapsed
                            rem_s = int((f_size * (1 - f_percent)) / speed)
                            eta = f"Осталось: {rem_s // 60} мин. {rem_s % 60} сек." if rem_s > 60 else f"Осталось: {rem_s} сек."
                        else:
                            eta = "Расчет..."
                        progress_cb(overall, eta)
                    check_stop = lambda: self.stop_signal
                    res = self.encryptor.encrypt_file(f_path, out_path, key, update_ui, check_stop) if mode == "encrypt" else self.encryptor.decrypt_file(f_path, out_path, key, update_ui, check_stop)
                    if not res or self.stop_signal:
                        if os.path.exists(out_path):
                            os.remove(out_path)
                        break
                    success += 1
                    log_cb(f"Успешно: {name}")
                except Exception as e:
                    log_cb(f"Ошибка ({name}): {str(e)[:50]}")
                progress_cb((i + 1) / total_files, "")
            duration = time.time() - start_time
            m, s = int(duration // 60), int(duration % 60)
            time_str = f"{m} мин. {s} сек." if m > 0 else f"{s} сек."
            log_cb(f"{'Остановлено' if self.stop_signal else 'Завершено'} за {time_str}")
            finish_cb(success, total_files, time_str, self.stop_signal)
        except Exception as e:
            log_cb(f"Ошибка: {e}")
            finish_cb(0, total_files, "0 сек.", False)
