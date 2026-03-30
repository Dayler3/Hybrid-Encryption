import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
import hashlib
from src.core import KeyManager
from src.utils import ConfigManager, FileSystem, Hasher
from src.processor import CryptoProcessor

class LoginWindow(ctk.CTkToplevel):
    def __init__(self, parent, saved_hash, on_success):
        super().__init__(parent)
        self.on_success = on_success
        self.saved_hash = saved_hash
        self.is_registration = saved_hash is None
        
        self.title("Доступ к системе" if not self.is_registration else "Первая настройка")
        self.geometry("350x250")
        self.protocol("WM_DELETE_WINDOW", parent.destroy)
        self.attributes('-topmost', True)
        
        self.center_login_window()
        
        label_txt = "Придумайте пароль" if self.is_registration else "Введите пароль"
        ctk.CTkLabel(self, text=label_txt, font=("Roboto", 16, "bold")).pack(pady=(30, 10))
        
        self.pwd_entry = ctk.CTkEntry(self, show="*", width=250)
        self.pwd_entry.pack(pady=10)
        self.pwd_entry.bind("<Return>", lambda e: self.confirm())

        self.after(200, lambda: self.pwd_entry.focus_set())

        btn_txt = "СОЗДАТЬ И ВОЙТИ" if self.is_registration else "ВОЙТИ"
        self.btn = ctk.CTkButton(self, text=btn_txt, command=self.confirm, fg_color="#2980b9")
        self.btn.pack(pady=20)

    def center_login_window(self):
        self.update_idletasks()
        width, height = 350, 250
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')

    def confirm(self):
        pwd = self.pwd_entry.get()
        if not pwd: return
        
        pwd_hash = hashlib.sha256(pwd.encode()).hexdigest()
        
        if self.is_registration:
            if len(pwd) < 4:
                messagebox.showwarning("Внимание", "Пароль должен быть не менее 4 символов")
                return
            self.on_success(pwd_hash)
            self.destroy()
        else:
            if pwd_hash == self.saved_hash:
                self.on_success()
                self.destroy()
            else:
                self.pwd_entry.configure(fg_color=("#fadbd8", "#7b241c"))
                self.pwd_entry.delete(0, "end")


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.conf_manager = ConfigManager()
        self.config = self.conf_manager.load()
        
        self.withdraw()
        saved_hash = self.config.get("master_hash")
        self.login_window = LoginWindow(self, saved_hash, self.unlock_app)

        self.km = KeyManager()
        self.processor = CryptoProcessor(self.km)
        self.selected_files = []

        self._apply_theme(self.config["theme"])
        self.title("Hybrid Encryption v1.0")
        self.geometry("750x820")
        self.minsize(700, 750)

        if not os.path.exists("keys/private_key.pem"): 
            self.km.generate_keys()

        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(pady=10, padx=10, fill="both", expand=True)
        self.tabview.configure(segmented_button_selected_color=("#1f618d", "#2980b9"))
        self.tabview.add("Шифрование")
        self.tabview.add("Настройки")

        self.setup_crypto_tab()
        self.setup_settings_tab()

        self.textbox = ctk.CTkTextbox(self, height=140, font=("Consolas", 12), fg_color=("gray95", "gray10"))
        self.textbox.pack(pady=10, padx=20, fill="x")
        self.textbox.configure(state="disabled")

        self.info_label = ctk.CTkLabel(self, text="🛡️ AES-256-GCM | RSA-2048", font=("Roboto", 11), text_color="gray")
        self.info_label.place(relx=0.98, rely=0.99, anchor="se")

    def center_main_window(self):
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')

    def unlock_app(self, new_hash=None):
        if new_hash:
            self.config["master_hash"] = new_hash
            self.conf_manager.save(self.config)
        
        self.deiconify()
        self.center_main_window()
        self.log("Система разблокирована. Добро пожаловать.")

    def _apply_theme(self, theme_name):
        theme_map = {"Темная": "Dark", "Светлая": "Light", "Системная": "System"}
        ctk.set_appearance_mode(theme_map.get(theme_name, "Dark"))
        ctk.set_default_color_theme("blue")

    def log(self, msg):
        self.textbox.configure(state="normal")
        self.textbox.insert("end", f"> {msg}\n")
        self.textbox.see("end")
        self.textbox.configure(state="disabled")

    def setup_crypto_tab(self):
        tab = self.tabview.tab("Шифрование")
        ctk.CTkLabel(tab, text="Менеджер очереди файлов", font=("Roboto", 20, "bold")).pack(pady=10)

        btn_frame = ctk.CTkFrame(tab, fg_color="transparent")
        btn_frame.pack(fill="x", padx=100)
        
        ctk.CTkButton(btn_frame, text=" + ДОБАВИТЬ ", fg_color="#34495e", width=120, 
                      command=self.browse_files).pack(side="left", padx=10, expand=True)
        
        ctk.CTkButton(btn_frame, text=" 🧹 ОЧИСТИТЬ ", fg_color="#7f8c8d", width=120, 
                      command=self.clear_queue).pack(side="right", padx=10, expand=True)

        self.files_list_frame = ctk.CTkScrollableFrame(
            tab, 
            label_text="Очередь файлов",
            fg_color=("gray82", "gray12"),   
            border_width=2,                  
            border_color=("gray70", "gray25"),
            corner_radius=10
        )
        self.files_list_frame.pack(pady=10, padx=20, fill="both", expand=True)

        self.progress_label = ctk.CTkLabel(tab, text="Очередь пуста", font=("Roboto", 13))
        self.progress_label.pack(pady=(5, 0))
        self.progress_bar = ctk.CTkProgressBar(tab, width=400)
        self.progress_bar.set(0)
        self.progress_bar.pack(pady=5)

        self.refresh_file_list()

        self.btn_enc = ctk.CTkButton(tab, text="ЗАШИФРОВАТЬ ПАКЕТ", fg_color="#27ae60", 
                                     width=300, height=45, command=lambda: self.start_process("encrypt"))
        self.btn_enc.pack(pady=10)
        
        self.btn_dec = ctk.CTkButton(tab, text="РАСШИФРОВАТЬ ПАКЕТ", fg_color="#2980b9", 
                                     width=300, height=45, command=lambda: self.start_process("decrypt"))
        self.btn_dec.pack(pady=5)

        folder_btn_frame = ctk.CTkFrame(tab, fg_color="transparent")
        folder_btn_frame.pack(pady=5)
        
        ctk.CTkButton(folder_btn_frame, text="📁 Зашифрованные", font=("Roboto", 11), width=130, height=25, 
                      command=lambda: FileSystem.open_explorer(self.config["encrypt_dir"])).pack(side="left", padx=5)
        
        ctk.CTkButton(folder_btn_frame, text="📁 Расшифрованные", font=("Roboto", 11), width=130, height=25, 
                      command=lambda: FileSystem.open_explorer(self.config["decrypt_dir"])).pack(side="right", padx=5)

        self.status_label = ctk.CTkLabel(tab, text="", font=("Roboto", 14, "italic"), wraplength=500)
        self.status_label.pack(pady=5, fill="x")

    def refresh_file_list(self):
        for widget in self.files_list_frame.winfo_children(): 
            widget.destroy()
            
        if not self.selected_files:
            ctk.CTkLabel(self.files_list_frame, text="Список пуст...", text_color="gray").pack(pady=50)
            self.progress_label.configure(text="Очередь пуста")
            return

        total_size = 0
        for f_path in self.selected_files:
            row = ctk.CTkFrame(self.files_list_frame, fg_color=("gray95", "gray17"), corner_radius=6)
            row.pack(fill="x", padx=5, pady=3)
            
            name, size_str = os.path.basename(f_path), FileSystem.get_formatted_size(f_path)
            try: total_size += os.path.getsize(f_path)
            except: pass
            
            ctk.CTkLabel(row, text=f"📄 {name} ({size_str})", anchor="w").pack(side="left", padx=10, fill="x", expand=True)
            ctk.CTkButton(row, text="✕", width=28, height=28, fg_color="#c0392b", hover_color="#a93226", 
                         command=lambda p=f_path: self.remove_file_from_list(p)).pack(side="right", padx=5, pady=3)
        
        self.progress_label.configure(text=f"Файлов: {len(self.selected_files)} | Всего: {FileSystem.format_bytes(total_size)}")

    def start_process(self, mode):
        if not self.selected_files: return
        out_dir = self.config["encrypt_dir"] if mode == "encrypt" else self.config["decrypt_dir"]
        rus_mode = "ШИФРОВАНИЕ" if mode == "encrypt" else "РАСШИФРОВКА"
        self.log(f"--- Старт: {rus_mode} ---")
        
        success, total = self.processor.run(self.selected_files, mode, out_dir, self.progress_bar.set, self.log)
        self.status_label.configure(text=f" ✅  Завершено: {success} / {total}  ", text_color="#2ecc71")
        self.clear_queue()

    def browse_files(self):
        new_files = filedialog.askopenfilenames()
        if new_files:
            for f in new_files:
                if f not in self.selected_files: self.selected_files.append(f)
            self.refresh_file_list()

    def remove_file_from_list(self, file_path):
        if file_path in self.selected_files:
            self.selected_files.remove(file_path)
            self.refresh_file_list()

    def clear_queue(self):
        self.selected_files = []
        self.refresh_file_list()

    def setup_settings_tab(self):
        tab = self.tabview.tab("Настройки")
        ctk.CTkLabel(tab, text="Персонализация", font=("Roboto", 18, "bold")).pack(pady=(20, 10))
        
        theme_frame = ctk.CTkFrame(tab)
        theme_frame.pack(pady=5, padx=30)
        ctk.CTkLabel(theme_frame, text="Тема интерфейса:").pack(side="left", padx=20, pady=15)
        self.theme_menu = ctk.CTkOptionMenu(theme_frame, values=["Темная", "Светлая", "Системная"], command=self._apply_theme)
        self.theme_menu.set(self.config["theme"])
        self.theme_menu.pack(side="right", padx=20)
        
        ctk.CTkLabel(tab, text="Рабочие директории", font=("Roboto", 18, "bold")).pack(pady=(30, 10))
        self.enc_entry = self.add_path_row(tab, "Папка для шифрования (Выход):", self.config["encrypt_dir"])
        self.dec_entry = self.add_path_row(tab, "Папка для дешифрования (Выход):", self.config["decrypt_dir"])
        
        ctk.CTkButton(tab, text="СОХРАНИТЬ КОНФИГУРАЦИЮ", command=self.save_all, 
                      fg_color="#d35400", width=250, height=45).pack(pady=50)

    def add_path_row(self, tab, label_text, path):
        ctk.CTkLabel(tab, text=label_text).pack(pady=(10, 0))
        f = ctk.CTkFrame(tab); f.pack(pady=5, padx=30)
        entry = ctk.CTkEntry(f, width=400, fg_color=("white", "gray15"))
        entry.insert(0, path); entry.pack(side="left", padx=10, pady=10)
        ctk.CTkButton(f, text="Обзор", width=80, command=lambda e=entry: self.set_dir(e)).pack(side="right", padx=10)
        return entry

    def save_all(self):
        self.config["encrypt_dir"] = self.enc_entry.get()
        self.config["decrypt_dir"] = self.dec_entry.get()
        self.config["theme"] = self.theme_menu.get()
        self.conf_manager.save(self.config)
        self.log("Конфигурация успешно сохранена в файл.")

    def set_dir(self, entry):
        d = filedialog.askdirectory()
        if d: 
            entry.delete(0, "end")
            entry.insert(0, d)

if __name__ == "__main__":
    app = App()
    app.mainloop()