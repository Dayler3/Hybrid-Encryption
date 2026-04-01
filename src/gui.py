import customtkinter as ctk
from tkinter import filedialog
import os
import hashlib
from plyer import notification
from src.core import KeyManager
from src.utils import ConfigManager, FileSystem
from src.processor import CryptoProcessor


class LoginWindow(ctk.CTkToplevel):
    def __init__(self, parent, saved_hash, on_success):
        super().__init__(parent)
        self.on_success = on_success
        self.saved_hash = saved_hash
        self.is_reg = saved_hash is None
        self.title("Безопасность")
        self.geometry("350x250")
        self.resizable(False, False)
        self.attributes('-topmost', True)
        self.protocol("WM_DELETE_WINDOW", parent.destroy)
        self.center_window()
        ctk.CTkLabel(self, text="Мастер-пароль", font=("Roboto", 16, "bold")).pack(pady=(30, 10))
        self.pwd = ctk.CTkEntry(self, show="*", width=220)
        self.pwd.pack(pady=10)
        self.pwd.bind("<Return>", lambda e: self.confirm())
        ctk.CTkButton(self, text="ПОДТВЕРДИТЬ", command=self.confirm, width=150).pack(pady=20)
        self.after(200, self.pwd.focus_set)

    def center_window(self):
        self.update_idletasks()
        x, y = (self.winfo_screenwidth() // 2) - 175, (self.winfo_screenheight() // 2) - 125
        self.geometry(f"+{x}+{y}")

    def confirm(self):
        p = self.pwd.get()
        if not p:
            return
        h = hashlib.sha256(p.encode()).hexdigest()
        if self.is_reg or h == self.saved_hash:
            self.destroy()
            self.on_success(p, h if self.is_reg else None)
        else:
            self.pwd.configure(fg_color="#7b241c")


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.withdraw()
        self.conf_manager = ConfigManager()
        self.conf = self.conf_manager.load()
        self.km, self.proc = KeyManager(), CryptoProcessor(KeyManager())
        self.selected_files, self.m_pwd = [], None
        self.title("Hybrid Encryption v1.2")
        self.geometry("750x850")
        self.minsize(700, 800)
        ctk.set_appearance_mode("Dark" if self.conf.get("theme") == "Темная" else "Light")
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)
        self.tabview.add("Шифрование")
        self.tabview.add("Настройки")
        LoginWindow(self, self.conf.get("master_hash"), self.unlock)

    def unlock(self, pwd, new_hash=None):
        self.m_pwd = pwd
        if new_hash:
            self.conf["master_hash"] = new_hash
            self.conf_manager.save(self.conf)
        if not os.path.exists("keys/private_key.pem"):
            self.km.generate_keys(pwd)
        self.setup_ui()
        self.update_idletasks()
        x, y = (self.winfo_screenwidth() // 2) - 375, (self.winfo_screenheight() // 2) - 425
        self.geometry(f"+{x}+{y}")
        self.deiconify()

    def setup_ui(self):
        tab = self.tabview.tab("Шифрование")
        f_t = ctk.CTkFrame(tab, fg_color="transparent")
        f_t.pack(fill="x", padx=50, pady=10)
        ctk.CTkButton(f_t, text="+ ФАЙЛЫ", command=self.add_f, fg_color="#34495e").pack(side="left", expand=True, padx=5)
        ctk.CTkButton(f_t, text="ОЧИСТИТЬ", fg_color="#7f8c8d", command=self.clear).pack(side="right", expand=True, padx=5)
        self.list = ctk.CTkScrollableFrame(tab, label_text="Очередь", border_width=2, corner_radius=10)
        self.list.pack(fill="both", expand=True, padx=20, pady=10)
        self.p_label = ctk.CTkLabel(tab, text="Очередь пуста")
        self.p_label.pack()
        self.p_bar = ctk.CTkProgressBar(tab, width=450)
        self.p_bar.set(0)
        self.p_bar.pack(pady=5)
        self.btn_enc = ctk.CTkButton(tab, text="ЗАШИФРОВАТЬ", fg_color="#27ae60", height=40, command=lambda: self.start("encrypt"))
        self.btn_enc.pack(pady=5)
        self.btn_dec = ctk.CTkButton(tab, text="РАСШИФРОВАТЬ", fg_color="#2980b9", height=40, command=lambda: self.start("decrypt"))
        self.btn_dec.pack(pady=5)
        self.btn_stop = ctk.CTkButton(tab, text="ОТМЕНИТЬ", fg_color="#c0392b", height=40, command=self.proc.stop)
        f_b = ctk.CTkFrame(tab, fg_color="transparent")
        f_b.pack(pady=10)
        ctk.CTkButton(f_b, text="📁 Зашифрованные", width=140, command=lambda: FileSystem.open_explorer(self.conf["encrypt_dir"])).pack(side="left", padx=5)
        ctk.CTkButton(f_b, text="📁 Расшифрованные", width=140, command=lambda: FileSystem.open_explorer(self.conf["decrypt_dir"])).pack(side="right", padx=5)
        self.log_box = ctk.CTkTextbox(self, height=120, font=("Consolas", 12))
        self.log_box.pack(fill="x", padx=10, pady=10)
        self.log_box.configure(state="disabled")
        ctk.CTkLabel(tab, text="RSA-2048 | AES-256-CTR", font=("Roboto", 11), text_color="gray").pack(side="bottom", anchor="e", padx=20, pady=5)
        self.refresh()
        self.setup_settings()

    def refresh(self):
        for w in self.list.winfo_children():
            w.destroy()
        if not self.selected_files:
            self.p_label.configure(text="Пусто")
            return
        sz = 0
        for f in self.selected_files:
            r = ctk.CTkFrame(self.list)
            r.pack(fill="x", padx=5, pady=2)
            ctk.CTkLabel(r, text=f"📄 {os.path.basename(f)}").pack(side="left", padx=10)
            ctk.CTkButton(r, text="✕", width=28, fg_color="#c0392b", command=lambda p=f: self.remove_f(p)).pack(side="right", padx=5)
            try:
                sz += os.path.getsize(f)
            except:
                pass
        self.p_label.configure(text=f"Файлов: {len(self.selected_files)} | {FileSystem.format_bytes(sz)}")

    def setup_settings(self):
        tab = self.tabview.tab("Настройки")
        self.m_theme = ctk.CTkOptionMenu(tab, values=["Темная", "Светлая"], command=lambda t: ctk.set_appearance_mode("Dark" if t == "Темная" else "Light"))
        self.m_theme.set(self.conf.get("theme", "Темная"))
        self.m_theme.pack(pady=10)
        self.ent_enc = self.add_row(tab, "Папка шифрования:", self.conf["encrypt_dir"])
        self.ent_dec = self.add_row(tab, "Папка дешифрования:", self.conf["decrypt_dir"])
        ctk.CTkButton(tab, text="СОХРАНИТЬ", fg_color="#d35400", command=self.save_all).pack(pady=20)

    def add_row(self, tab, txt, path):
        ctk.CTkLabel(tab, text=txt).pack()
        f = ctk.CTkFrame(tab)
        f.pack(fill="x", padx=30)
        e = ctk.CTkEntry(f)
        e.insert(0, path)
        e.pack(side="left", fill="x", expand=True, padx=5)
        ctk.CTkButton(f, text="Обзор", width=60, command=lambda: self.set_dir(e)).pack(side="right")
        return e

    def save_all(self):
        self.conf["encrypt_dir"], self.conf["decrypt_dir"], self.conf["theme"] = self.ent_enc.get(), self.ent_dec.get(), self.m_theme.get()
        self.conf_manager.save(self.conf)
        self.write_log("Настройки сохранены.")

    def set_dir(self, e):
        d = filedialog.askdirectory()
        if d:
            e.delete(0, 'end')
        e.insert(0, d)

    def add_f(self):
        for f in filedialog.askopenfilenames():
            if f not in self.selected_files:
                self.selected_files.append(f)
        self.refresh()

    def remove_f(self, p):
        if p in self.selected_files:
            self.selected_files.remove(p)
        self.refresh()

    def clear(self):
        self.selected_files = []
        self.refresh()

    def update_progress(self, val, eta):
        self.p_bar.set(val)
        if eta:
            self.p_label.configure(text=eta)

    def start(self, mode):
        if not self.selected_files:
            return
        self.btn_enc.pack_forget()
        self.btn_dec.pack_forget()
        self.btn_stop.pack(pady=5, after=self.p_bar)
        self.write_log(f"Старт: {'Шифрование' if mode=='encrypt' else 'Расшифровка'}")
        if mode == "encrypt":
            self.proc.run_async(self.selected_files, mode, self.conf["encrypt_dir"])
        else:
            self.conf(["decrypt_dir"], self.update_progress, self.write_log, self.finish, self.m_pwd)

    def write_log(self, msg):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"> {msg}\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def finish(self, s, t, time_taken, stopped):
        if not stopped:
            try:
                notification.notify(title="Hybrid Encryption v1.2", message=f"Готово: {s}/{t} за {time_taken}", timeout=10)
            except:
                pass
        self.btn_stop.pack_forget()
        self.btn_enc.pack(pady=5, after=self.p_bar)
        self.btn_dec.pack(pady=5, after=self.btn_enc)
        self.write_log(f"ИТОГ: {s} из {t} готово за {time_taken}")
        self.refresh()
        self.p_bar.set(0)
