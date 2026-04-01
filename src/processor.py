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
        total_files, success, start_time = len(files), 0, time.time()
        is_enc, check_stop = (mode == "encrypt"), lambda: self.stop_signal
        try:
            key = self.km.load_public_key() if is_enc else self.km.load_private_key(password)
            for i, f_path in enumerate(files):
                if self.stop_signal:
                    break
                name, f_size, f_start = os.path.basename(f_path), os.path.getsize(f_path), time.time()
                out_name = name + ".enc" if is_enc else name.replace(".enc", "")
                out_path = os.path.join(out_dir, out_name)

                def update_ui(f_percent, f_idx=i, f_st=f_start, f_sz=f_size):
                    overall = (f_idx / total_files) + (f_percent / total_files)
                    elapsed = time.time() - f_st
                    if elapsed > 0 and f_percent > 0:
                        speed = (f_sz * f_percent) / elapsed
                        rem_s = int((f_sz * (1 - f_percent)) / speed)
                        m, s = divmod(rem_s, 60)
                        eta = f"Осталось: {m} мин. {s} сек." if m > 0 else f"Осталось: {s} сек."
                    else:
                        eta = "Расчет..."
                    progress_cb(overall, eta)
                try:
                    res = self.encryptor.encrypt_file(f_path, out_path, key, update_ui, check_stop) if is_enc else \
                        self.encryptor.decrypt_file(f_path, out_path, key, update_ui, check_stop)
                    if not res or self.stop_signal:
                        if os.path.exists(out_path):
                            os.remove(out_path)
                        break
                    success += 1
                    log_cb(f"Успешно: {name}")
                except Exception as e:
                    log_cb(f"Ошибка ({name}): {str(e)[:50]}")
                    if os.path.exists(out_path):
                        os.remove(out_path)
                progress_cb((i + 1) / total_files, "")
            m, s = divmod(int(time.time() - start_time), 60)
            t_str = f"{m} мин. {s} сек." if m > 0 else f"{s} сек."
            log_cb(f"{'Остановлено' if self.stop_signal else 'Завершено'} за {t_str}")
            finish_cb(success, total_files, t_str, self.stop_signal)
        except Exception as e:
            log_cb(f"Ошибка: {e}")
            finish_cb(0, total_files, "0 сек.", False)
