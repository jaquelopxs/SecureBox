<<<<<<< HEAD
import os  # Para manipular arquivos e gerar bytes aleatórios
from getpass import getpass  # Para ler a senha sem mostrar na tela
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # Função para derivar chave da senha
from cryptography.hazmat.primitives import hashes  # Algoritmo hash para o KDF
from cryptography.hazmat.backends import default_backend  # Backend padrão da criptografia
from cryptography.fernet import Fernet  # Para criptografia simétrica segura
import base64  # Para codificar chave para o formato esperado pelo Fernet

#Gerar salt aleatório
def gerar_salt():
    return os.urandom(16) # 16 bytes aleatórios

# Deriva uma chave forte da senha + salt usando PBKDF2HMAC
def derivar_chave(senha, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), #Algoritmo hash SHA-256
        length=32, # Tamanho da chave em bytes
        salt=salt,
        iterations=100_000, #numero de iterações para tornar lento ataques e força bruta
        backend=default_backend() #Backend padrão do sistema
    )
    chave=kdf.derive(senha.encode()) #Deriva a chave a parti da senha codificada em bytes
    return base64.urlsafe_b64encode(chave)

#Função principal que criptografa o arquivo com a chave derivada da senha
def criptografar_arquivo(nome_arquivo, senha):
    salt = gerar_salt()
    chave = derivar_chave(senha, salt)
    fernet = Fernet(chave)

    with open(nome_arquivo, "rb") as files:
        dados = files.read()
    
    dados_criptografados = fernet.encrypt(dados)

    with open(nome_arquivo + ".cripto", "wb") as files:
        files.write(salt + dados_criptografados) # Grava os bytes no novo arquivo

    print(f"Arquivo '{nome_arquivo}' criptografado com sucesso!")

#Função que roda o script
def main():
    nome_arquivo = input("Nome do arquivo para critptografar:")
    if not os.path.exists(nome_arquivo):
        print("Arquivo não encontrado")
        return
    senha = getpass("Digite a senha para criptografar: ")
    criptografar_arquivo(nome_arquivo, senha)

if __name__ == "__main__":
=======
import os  # Para manipular arquivos e gerar bytes aleatórios
from getpass import getpass  # Para ler a senha sem mostrar na tela
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # Função para derivar chave da senha
from cryptography.hazmat.primitives import hashes  # Algoritmo hash para o KDF
from cryptography.hazmat.backends import default_backend  # Backend padrão da criptografia
from cryptography.fernet import Fernet  # Para criptografia simétrica segura
import base64  # Para codificar chave para o formato esperado pelo Fernet

#Gerar salt aleatório
def gerar_salt():
    return os.urandom(16) # 16 bytes aleatórios

# Deriva uma chave forte da senha + salt usando PBKDF2HMAC
def derivar_chave(senha, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), #Algoritmo hash SHA-256
        length=32, # Tamanho da chave em bytes
        salt=salt,
        iterations=100_000, #numero de iterações para tornar lento ataques e força bruta
        backend=default_backend() #Backend padrão do sistema
    )
    chave=kdf.derive(senha.encode()) #Deriva a chave a parti da senha codificada em bytes
    return base64.urlsafe_b64encode(chave)

#Função principal que criptografa o arquivo com a chave derivada da senha
def criptografar_arquivo(nome_arquivo, senha):
    salt = gerar_salt()
    chave = derivar_chave(senha, salt)
    fernet = Fernet(chave)

    with open(nome_arquivo, "rb") as files:
        dados = files.read()
    
    dados_criptografados = fernet.encrypt(dados)

    with open(nome_arquivo + ".cripto", "wb") as files:
        files.write(salt + dados_criptografados) # Grava os bytes no novo arquivo

    print(f"Arquivo '{nome_arquivo}' criptografado com sucesso!")

#Função que roda o script
def main():
    nome_arquivo = input("Nome do arquivo para critptografar:")
    if not os.path.exists(nome_arquivo):
        print("Arquivo não encontrado")
        return
    senha = getpass("Digite a senha para criptografar: ")
    criptografar_arquivo(nome_arquivo, senha)

if __name__ == "__main__":
>>>>>>> 97c12fd88410afebe8a0955326cbcd62ee13e7dc
    main()