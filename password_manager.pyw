import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from cryptography.fernet import Fernet
import os
import datetime
import re
import random
import string

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PASSWORD MANAGER - Creato da Marco Filippone")
        self.root.geometry("500x400")

        # Imposta i file di lavoro
        self.key_file = "secret.key"
        self.password_file = "passwords.txt"
        self.activity_log_file = "activity_log.txt"
        self.admin_password_file = "admin_password.txt"

        # Crea interfaccia utente
        self.create_widgets()
        self.check_session()

        # Verifica se la chiave esiste
        if not os.path.exists(self.key_file):
            self.create_key()

        self.key = self.load_key()

        # Verifica se la password admin è impostata e chiede l'autenticazione
        if not os.path.exists(self.admin_password_file):
            self.set_admin_password()
        else:
            self.prompt_admin_password()

        # Gestisci il timeout della sessione
        self.root.after(60000, self.check_timeout)

    def create_widgets(self):
        # Frame principale
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Pulsanti principali
        self.add_button = ttk.Button(self.main_frame, text="Aggiungi Servizio", command=self.add_password)
        self.add_button.grid(row=0, column=0, pady=5, sticky=tk.W)

        self.view_button = ttk.Button(self.main_frame, text="Visualizza Servizi", command=self.view_passwords)
        self.view_button.grid(row=0, column=1, pady=5, sticky=tk.W)

        self.modify_button = ttk.Button(self.main_frame, text="Modifica Servizio", command=self.modify_password)
        self.modify_button.grid(row=1, column=0, pady=5, sticky=tk.W)

        self.delete_button = ttk.Button(self.main_frame, text="Cancella Servizio", command=self.delete_password)
        self.delete_button.grid(row=1, column=1, pady=5, sticky=tk.W)

        self.backup_button = ttk.Button(self.main_frame, text="Backup", command=self.create_backup)
        self.backup_button.grid(row=2, column=0, pady=5, sticky=tk.W)

        self.restore_button = ttk.Button(self.main_frame, text="Ripristina", command=self.restore_backup)
        self.restore_button.grid(row=2, column=1, pady=5, sticky=tk.W)

        self.logout_button = ttk.Button(self.main_frame, text="Logout", command=self.logout)
        self.logout_button.grid(row=3, column=0, columnspan=2, pady=5, sticky=tk.W)

        # Input service
        self.service_label = ttk.Label(self.main_frame, text="Nome Servizio:")
        self.service_label.grid(row=4, column=0, sticky=tk.W, pady=5)
        self.service_entry = ttk.Entry(self.main_frame)
        self.service_entry.grid(row=4, column=1, pady=5)

        # Input password
        self.password_label = ttk.Label(self.main_frame, text="Password:")
        self.password_label.grid(row=5, column=0, sticky=tk.W, pady=5)
        self.password_entry = ttk.Entry(self.main_frame, show="*")
        self.password_entry.grid(row=5, column=1, pady=5)

    def create_key(self):
        key = Fernet.generate_key()
        with open(self.key_file, "wb") as key_file:
            key_file.write(key)

    def load_key(self):
        return open(self.key_file, "rb").read()

    def encrypt_password(self, password, key):
        cipher = Fernet(key)
        return cipher.encrypt(password.encode())

    def decrypt_password(self, encrypted_password, key):
        cipher = Fernet(key)
        return cipher.decrypt(encrypted_password).decode()

    def is_strong_password(self, password):
        if (len(password) < 8 or
            not re.search(r"[A-Z]", password) or
            not re.search(r"[a-z]", password) or
            not re.search(r"[0-9]", password) or
            not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)):
            return False
        return True

    def clear_entries(self):
        self.service_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)

    def add_password(self):
        service = self.service_entry.get().strip()
        password = self.password_entry.get().strip()

        if not service or not password:
            messagebox.showwarning("Campi Mancanti", "Nome del servizio e password sono obbligatori.")
            return

        if not self.is_strong_password(password):
            messagebox.showwarning("Password Debole", "La password deve essere almeno 8 caratteri, con lettere maiuscole, minuscole, numeri e simboli.")
            return

        encrypted_password = self.encrypt_password(password, self.key)
        with open(self.password_file, "a") as f:
            f.write(f"{service}:{encrypted_password.decode()}\n")

        self.log_activity(f"Aggiunto servizio: {service}")
        self.clear_entries()
        messagebox.showinfo("Successo", "Servizio e password aggiunti con successo!")

    def view_passwords(self):
        if not os.path.exists(self.password_file):
            messagebox.showwarning("Nessuna Password", "Nessuna password salvata.")
            return

        view_window = tk.Toplevel(self.root)
        view_window.title("Servizi e Password")

        text = tk.Text(view_window, wrap="word", height=15, width=60)
        text.pack(padx=10, pady=10)

        with open(self.password_file, "r") as f:
            for line in f:
                service, encrypted_password = line.strip().split(":")
                decrypted_password = self.decrypt_password(encrypted_password.encode(), self.key)
                text.insert(tk.END, f"Servizio: {service}, Password: {decrypted_password}\n")

    def modify_password(self):
        service = simpledialog.askstring("Modifica Servizio", "Inserisci il nome del servizio da modificare:")
        if not service:
            return

        found = False
        temp_file = "temp.txt"

        with open(self.password_file, "r") as f, open(temp_file, "w") as temp:
            for line in f:
                if line.startswith(f"{service}:"):
                    found = True
                    old_password = line.strip().split(":")[1]
                    decrypted_password = self.decrypt_password(old_password.encode(), self.key)
                    new_password = simpledialog.askstring("Modifica Password", f"Inserisci la nuova password per {service} (attuale: {decrypted_password}):", show="*")
                    
                    if new_password and self.is_strong_password(new_password):
                        encrypted_password = self.encrypt_password(new_password, self.key)
                        temp.write(f"{service}:{encrypted_password.decode()}\n")
                    else:
                        messagebox.showwarning("Password Debole", "La password deve essere almeno 8 caratteri, con lettere maiuscole, minuscole, numeri e simboli.")
                        temp.write(line)
                else:
                    temp.write(line)

        if found:
            os.replace(temp_file, self.password_file)
            self.log_activity(f"Modificato servizio: {service}")
            messagebox.showinfo("Successo", "Password modificata con successo!")
        else:
            os.remove(temp_file)
            messagebox.showwarning("Servizio Non Trovato", "Servizio non trovato.")

    def delete_password(self):
        service = simpledialog.askstring("Cancella Servizio", "Inserisci il nome del servizio da cancellare:")
        if not service:
            return

        found = False
        temp_file = "temp.txt"

        with open(self.password_file, "r") as f, open(temp_file, "w") as temp:
            for line in f:
                if not line.startswith(f"{service}:"):
                    temp.write(line)
                else:
                    found = True

        if found:
            os.replace(temp_file, self.password_file)
            self.log_activity(f"Cancellato servizio: {service}")
            messagebox.showinfo("Successo", "Servizio cancellato con successo!")
        else:
            os.remove(temp_file)
            messagebox.showwarning("Servizio Non Trovato", "Servizio non trovato.")

    def create_backup(self):
        backup_file = "backup.txt"
        if os.path.exists(backup_file):
            os.remove(backup_file)
        with open(self.password_file, "r") as original, open(backup_file, "w") as backup:
            backup.write(original.read())
        self.log_activity(f"Backup creato: {backup_file}")
        messagebox.showinfo("Backup Completo", f"Backup sovrascritto come {backup_file}")

    def restore_backup(self):
        backup_file = "backup.txt"
        if not os.path.exists(backup_file):
            messagebox.showwarning("Nessun Backup", "Nessun backup disponibile.")
            return

        with open(backup_file, "r") as f:
            with open(self.password_file, "w") as original:
                original.write(f.read())
        self.log_activity(f"Ripristinato da backup: {backup_file}")
        messagebox.showinfo("Ripristino Completo", "Servizi ripristinati dal backup.")

    def set_admin_password(self):
        password = simpledialog.askstring("Imposta Password Admin", "Imposta una nuova password per l'amministratore:", show="*")
        if password and self.is_strong_password(password):
            with open(self.admin_password_file, "w") as f:
                f.write(password)
            self.log_activity("Password admin impostata.")
        else:
            messagebox.showwarning("Password Debole", "La password deve essere almeno 8 caratteri, con lettere maiuscole, minuscole, numeri e simboli.")
            self.root.destroy()

    def prompt_admin_password(self):
        password = simpledialog.askstring("Autenticazione Admin", "Inserisci la password admin:", show="*")
        if not password or not self.check_admin_password(password):
            messagebox.showerror("Errore", "Password admin errata.")
            self.root.destroy()

    def check_admin_password(self, password):
        with open(self.admin_password_file, "r") as f:
            stored_password = f.read().strip()
        return password == stored_password

    def logout(self):
        self.root.destroy()

    def log_activity(self, action):
        with open(self.activity_log_file, "a") as f:
            f.write(f"{datetime.datetime.now()}: {action}\n")

    def check_session(self):
        self.session_start_time = datetime.datetime.now()

    def check_timeout(self):
        if (datetime.datetime.now() - self.session_start_time).total_seconds() > 3600:  # Timeout di 1 ora
            self.logout()
        else:
            self.root.after(60000, self.check_timeout)  # Controlla ogni minuto

    def generate_password(self, length=12):
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(characters) for _ in range(length))

# Funzione principale
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
