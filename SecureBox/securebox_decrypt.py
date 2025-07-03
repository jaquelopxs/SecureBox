import os
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64

# Deriva a chave da senha + salt (igual no encrypt)
def derivar_chave(senha, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    chave = kdf.derive(senha.encode())
    return base64.urlsafe_b64encode(chave)

def descriptografar_arquivo(nome_arquivo_cripto, senha):
    with open(nome_arquivo_cripto, "rb") as file:
        salt = file.read(16)  # Lê os primeiros 16 bytes (salt)
        dados_criptografados = file.read()  # Lê o resto (dados criptografados)

    chave = derivar_chave(senha, salt)  # Deriva a chave com senha + salt
    fernet = Fernet(chave)  # Cria objeto Fernet para descriptografia

    try:
        dados = fernet.decrypt(dados_criptografados)  # Tenta descriptografar
    except Exception:
        print("Senha incorreta ou arquivo corrompido!")
        return

    nome_arquivo_recuperado = nome_arquivo_cripto.replace(".cripto", ".recuperado")

    with open(nome_arquivo_recuperado, "wb") as file:
        file.write(dados)  # Salva o arquivo descriptografado

    print(f"Arquivo descriptografado e salvo como '{nome_arquivo_recuperado}'")

def main():
    nome_arquivo_cripto = input("Nome do arquivo para descriptografar: ")
    if not os.path.exists(nome_arquivo_cripto):
        print("Arquivo não encontrado!")
        return

    senha = getpass("Digite a senha para descriptografar: ")
    descriptografar_arquivo(nome_arquivo_cripto, senha)

if __name__ == "__main__":
    main()
