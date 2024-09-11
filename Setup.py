import os
import platform

try:
    from win32com.client import Dispatch
except ImportError:
    Dispatch = None

def generate_key():
    """Genera una chiave crittografica e la salva in un file."""
    from cryptography.fernet import Fernet
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def set_admin_password():
    """Chiede all'utente di impostare una password di amministratore e la salva."""
    password = input("Inserisci la nuova password di amministratore: ")
    with open("admin_password.txt", "w") as admin_file:
        admin_file.write(password)

def make_read_only(file_path):
    """Rende un file in sola lettura."""
    os.chmod(file_path, 0o444)  # Imposta il file come read-only su tutti i sistemi

if __name__ == "__main__":
    if not os.path.exists("secret.key"):
        print("Generazione della chiave crittografica...")
        generate_key()
    if not os.path.exists("admin_password.txt"):
        print("Impostazione della password di amministratore...")
        set_admin_password()
    
    # Rendi il file Python in sola lettura
    make_read_only(__file__)
    
    print("Setup completato.")
 