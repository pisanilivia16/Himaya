"""
Arquivo: arquivovulneravel/app.py
Descrição: Aplicação Flask INTENCIONALMENTE VULNERÁVEL para fins acadêmicos.

⚠ ATENÇÃO: Este arquivo contém vulnerabilidades de segurança propositais.
   Serve exclusivamente como alvo dos testes do scanner de segurança do TCC.
   NÃO utilizar em produção ou em ambientes reais.

Vulnerabilidades presentes:
  - SQL Injection via concatenação de string na query de login
  - Ausência de hash nas senhas (armazenadas em plaintext)
  - Sem rate limiting (vulnerável a força bruta)
  - Sem validação ou sanitização de entrada
  - Sem proteção CSRF
"""

from flask import Flask, render_template, request
import sqlite3
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "teste_vulneravel.db")


def conectar() -> sqlite3.Connection:
    """Conecta ao banco de dados local da aplicação vulnerável."""
    return sqlite3.connect(DB_PATH)


def inicializar_banco() -> None:
    """
    Cria a tabela de usuários com senhas em PLAINTEXT — vulnerabilidade intencional.
    Não utiliza bcrypt nem qualquer forma de hash.
    """
    con = conectar()
    cursor = con.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT UNIQUE NOT NULL,
            senha   TEXT NOT NULL
        )
    """)

    # Senhas armazenadas em plaintext — vulnerabilidade intencional
    usuarios = [
        ("admin",  "123456"),
        ("user1",  "abc123"),
        ("root",   "root"),
    ]

    cursor.executemany(
        "INSERT OR IGNORE INTO usuarios (usuario, senha) VALUES (?, ?)",
        usuarios
    )

    con.commit()
    con.close()


@app.route("/")
def home():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():
    """
    Rota de login VULNERÁVEL.

    Vulnerabilidades:
      1. SQL Injection: query montada por concatenação de strings.
         Payload como ' OR '1'='1 autentica qualquer usuário.
      2. Sem rate limiting: aceita infinitas tentativas (força bruta).
      3. Sem sanitização: entradas como <script> são aceitas sem filtro.
      4. Senhas em plaintext: comparação direta sem hash.
    """
    usuario = request.form.get("usuario", "")
    senha   = request.form.get("senha", "")

    con = conectar()
    cursor = con.cursor()

    # ── VULNERÁVEL: SQL Injection por concatenação ──────────────────────────
    query = f"SELECT * FROM usuarios WHERE usuario='{usuario}' AND senha='{senha}'"
    cursor.execute(query)
    # ────────────────────────────────────────────────────────────────────────

    resultado = cursor.fetchone()
    con.close()

    if resultado:
        return "Login realizado!"

    return "Usuário ou senha incorretos"


# Inicializa o banco ao subir a aplicação
inicializar_banco()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))

    print(f"\n⚠  ATENÇÃO: Aplicação VULNERÁVEL rodando na porta {port}")
    print("   Use apenas para testes do scanner de segurança.\n")

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
