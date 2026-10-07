"""
Arquivo: arquivovulneravel/app.py
Descrição: Aplicação Flask INTENCIONALMENTE VULNERÁVEL para fins acadêmicos.

⚠ ATENÇÃO: Este arquivo contém vulnerabilidades de segurança propositais.
   Serve exclusivamente como alvo dos testes do scanner de segurança do TCC.
   NÃO utilizar em produção ou em ambientes reais.

Vulnerabilidades presentes:
  - SQL Injection via concatenação de string na query de login e cadastro
  - Ausência de hash nas senhas (armazenadas em plaintext)
  - Sem rate limiting (vulnerável a força bruta)
  - Sem validação ou sanitização de entrada
  - Cadastro sem política de senha (aceita vazia, curta, sem complexidade)
  - Cadastro sem validação de formato de e-mail
  - Cadastro sem checagem de duplicidade (usuário/e-mail)
  - Sem proteção CSRF
"""

from flask import Flask, render_template, request, jsonify
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

    # Sem UNIQUE em e-mail de propósito — o cadastro vulnerável não
    # impede duplicidade.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT UNIQUE NOT NULL,
            email   TEXT,
            senha   TEXT NOT NULL
        )
    """)

    # Senhas armazenadas em plaintext — vulnerabilidade intencional
    usuarios = [
        ("admin",  "admin@vulneravel.local",  "123456"),
        ("user1",  "user1@vulneravel.local",  "abc123"),
        ("root",   "root@vulneravel.local",   "root"),
    ]

    cursor.executemany(
        "INSERT OR IGNORE INTO usuarios (usuario, email, senha) VALUES (?, ?, ?)",
        usuarios
    )

    con.commit()
    con.close()


def _pagina_resultado(sucesso: bool, titulo: str, mensagem: str,
                       status: int = 200, voltar_para: str = "/",
                       mostrar_login: bool = False):
    """
    Responde em JSON (sucesso/titulo/mensagem), com o status HTTP certo.
    O front-end (login.html/cadastro.html) usa isso pra mostrar uma
    mensagem inline, SEM navegar pra outra página.
    """
    return jsonify(sucesso=sucesso, titulo=titulo, mensagem=mensagem), status


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
        return _pagina_resultado(
            True, "Login realizado!",
            f"Você entrou como '{usuario}'. Esse app não valida credenciais com segurança "
            "— por isso o scanner consegue burlá-lo.",
        )

    return _pagina_resultado(
        False, "Usuário ou senha incorretos",
        "Verifique seus dados e tente novamente.",
        status=401, voltar_para="/",
    )


@app.route("/cadastro")
def cadastro_form():
    return render_template("cadastro.html")


@app.route("/cadastro", methods=["POST"])
def cadastro():
    """
    Rota de cadastro VULNERÁVEL.

    Vulnerabilidades:
      1. Nenhuma política de senha: aceita vazia, curta, sem complexidade.
      2. Nenhuma validação de formato de e-mail.
      3. Nenhuma checagem de usuário/e-mail duplicado.
      4. Senha armazenada em plaintext.
      5. SQL Injection: INSERT montado por concatenação de string.
    """
    usuario = request.form.get("usuario", "")
    email   = request.form.get("email", "")
    senha   = request.form.get("senha", "")

    con = conectar()
    cursor = con.cursor()

    # ── VULNERÁVEL: INSERT por concatenação, sem validação alguma ──────────
    query = f"INSERT INTO usuarios (usuario, email, senha) VALUES ('{usuario}', '{email}', '{senha}')"
    try:
        cursor.execute(query)
        con.commit()
    except Exception as e:
        con.close()
        return _pagina_resultado(
            False, "Erro ao cadastrar", str(e),
            status=500, voltar_para="/cadastro",
        )
    # ────────────────────────────────────────────────────────────────────────

    con.close()
    return _pagina_resultado(
        True, "Cadastro realizado!",
        f"Conta de '{usuario}' criada — sem checar política de senha, "
        "formato de e-mail ou duplicidade. A senha foi gravada em plaintext.",
        mostrar_login=True,
    )


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
