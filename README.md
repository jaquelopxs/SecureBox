# SecureBox

SecureBox é uma aplicação simples de criptografia simétrica desenvolvida em Python, que permite ao usuário proteger arquivos locais utilizando uma senha. É ideal para armazenar com segurança dados sensíveis, como senhas e informações pessoais, mantendo tudo offline e protegido.

## Objetivo

Proteger qualquer arquivo de texto local, tornando seu conteúdo completamente ilegível sem a senha correta.

## ⚙️ Tecnologias e Conceitos Utilizados

- **Criptografia Simétrica (Fernet/AES)**
- **Salt Aleatório** para fortalecer a derivação da chave
- **PBKDF2HMAC** com 100.000 iterações (SHA-256)
- **Base64 (URL-safe)** para codificação da chave
- `getpass` para digitar a senha com segurança no terminal

## Como funciona

1. Você fornece um arquivo legível (ex: `senhas.txt`)
2. Executa `securebox_encrypt.py`
3. Digita uma senha de sua escolha
4. O arquivo é criptografado e salvo como `senhas.txt.cripto`
5. Você pode deletar o original com segurança

Quando quiser recuperar:

1. Executa `securebox_decrypt.py`
2. Digita a **mesma senha**
3. O conteúdo original é restaurado

## Requisitos

- Python 3.6 ou superior
- Biblioteca `cryptography`

```bash
pip install cryptography
````

---

## Segurança
* Sem a senha correta, o arquivo criptografado não pode ser recuperado.
* O salt é embutido no início do arquivo `.cripto`.
* A chave nunca é salva: ela é derivada da senha no momento da execução.
* A criptografia usada é autenticada e segura (Fernet = AES 128 + HMAC).


##Autora

Feito com foco em aprendizado e segurança por [Jaqueline Lopes](https://github.com/jaquelopxs)
