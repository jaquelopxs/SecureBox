import os
import base64
import hashlib
import itertools
import string
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ========================
# CONFIGURAÇÕES
# ========================
ARQUIVO = "senhas.txt.cripto"
TAMANHO_CHAVE = 32  # Fernet requer chave de 32 bytes (antes do base64)

# ========================
# GERA SENHAS CURTAS (para testes)
# ========================
def gerar_senhas(chars, min_len=4, max_len=5):
    for tam in range(min_len, max_len + 1):
        for comb in itertools.product(chars, repeat=tam):
            yield ''.join(comb)

# ========================
# DERIVAÇÃO DE CHAVE COM MÚLTIPLOS MÉTODOS
# ========================
def derivar_chaves_possiveis(senha, salt):
    chaves = []

    # 1. PBKDF2 com SHA256
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=TAMANHO_CHAVE,
            salt=salt,
            iterations=100_000,
            backend=default_backend()
        )
        chave_pbkdf2 = base64.urlsafe_b64encode(kdf.derive(senha.encode()))
        chaves.append(("PBKDF2-SHA256", chave_pbkdf2))
    except Exception as e:
        pass

    # 2. SHA256 puro
    try:
        sha256_raw = hashlib.sha256(senha.encode()).digest()
        chave_sha256 = base64.urlsafe_b64encode(sha256_raw)
        chaves.append(("SHA256", chave_sha256))
    except Exception as e:
        pass

    # 3. SHA512 truncado
    try:
        sha512_raw = hashlib.sha512(senha.encode()).digest()[:TAMANHO_CHAVE]
        chave_sha512 = base64.urlsafe_b64encode(sha512_raw)
        chaves.append(("SHA512-trunc", chave_sha512))
    except Exception as e:
        pass

    # 4. Senha usada diretamente como bytes (inseguro)
    try:
        senha_raw = senha.encode().ljust(TAMANHO_CHAVE, b'\0')[:TAMANHO_CHAVE]
        chave_raw = base64.urlsafe_b64encode(senha_raw)
        chaves.append(("RAW-PASS", chave_raw))
    except Exception as e:
        pass

    return chaves

# ========================
# ATAQUE DE BRUTE-FORCE COMPLETO
# ========================
def brute_force_fernet(dados):
    salt = dados[:16]
    token = dados[16:]

    resultados = []
    total_testadas = 0

    charset = string.ascii_lowercase + string.digits

    print("[*] Iniciando brute-force...")
    for senha in gerar_senhas(charset):
        total_testadas += 1
        chaves = derivar_chaves_possiveis(senha, salt)

        for metodo, chave in chaves:
            try:
                f = Fernet(chave)
                texto = f.decrypt(token).decode('utf-8', errors='replace')
                resultado = f"[✔] SENHA: '{senha}' | MÉTODO: {metodo}\n{texto}\n"
                print(resultado)
                resultados.append(resultado)
                # break aqui se quiser parar no primeiro sucesso

            except InvalidToken:
                continue
            except Exception as e:
                continue

        if total_testadas % 1000 == 0:
            print(f"→ {total_testadas} senhas testadas...")

    print(f"[✓] Total de senhas testadas: {total_testadas}")
    return resultados

# ========================
# EXECUÇÃO PRINCIPAL
# ========================
if __name__ == "__main__":
    if not os.path.exists(ARQUIVO):
        print(f"Arquivo '{ARQUIVO}' não encontrado.")
        exit()

    with open(ARQUIVO, "rb") as f:
        dados = f.read()

    resultados = brute_force_fernet(dados)

    if resultados:
        with open("resultado.txt", "w", encoding="utf-8") as f_out:
            for linha in resultados:
                f_out.write(linha + "\n" + "=" * 60 + "\n")
        print("[✔] Resultado salvo em 'resultado.txt'")
    else:
        print("[✘] Nenhuma senha ou método funcionou.")
