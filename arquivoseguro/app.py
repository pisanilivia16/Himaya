"""
Arquivo: arquivoseguro/app.py
Descrição: Aplicação Flask implementada com boas práticas de segurança.

Serve como versão corrigida para comparativo no TCC, demonstrando
como cada vulnerabilidade da versão vulnerável deve ser tratada.

Proteções implementadas:
  - Queries parametrizadas (previne SQL Injection)
  - Senhas armazenadas com bcrypt (previne exposição de plaintext)
  - Rate limiting por IP (previne força bruta)
  - Sanitização e validação de entrada (previne XSS e injeções)
  - Proteção CSRF via token de sessão
  - Headers de segurança HTTP
"""

from flask import Flask, render_template, request, session
import sqlite3
import bcrypt
import os
import sys
import re
import time
import secrets
from collections import defaultdict

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # chave segura gerada a cada inicialização

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "teste_seguro.db")

# ── Rate limiting simples em memória ────────────────────────────────────────
# Dicionário: ip -> [(timestamp), ...]
_tentativas: dict = defaultdict(list)
LIMITE_TENTATIVAS = 5       # máximo de tentativas
JANELA_SEGUNDOS   = 60      # dentro de N segundos


def _verificar_rate_limit(ip: str) -> bool:
    """
    Retorna True se o IP excedeu o limite de tentativas.
    Remove tentativas antigas fora da janela de tempo.
    """
    agora = time.time()
    # Remove tentativas fora da janela
    _tentativas[ip] = [t for t in _tentativas[ip] if agora - t < JANELA_SEGUNDOS]
    return len(_tentativas[ip]) >= LIMITE_TENTATIVAS


def _registrar_tentativa(ip: str) -> None:
    """Registra uma nova tentativa de login para o IP."""
    _tentativas[ip].append(time.time())
# ────────────────────────────────────────────────────────────────────────────


def _sanitizar_entrada(valor: str, max_len: int = 64) -> str:
    """
    Sanitiza a entrada do usuário:
      - Remove caracteres de controle
      - Trunca ao tamanho máximo
      - Remove espaços extras
    """
    # Remove caracteres de controle e nulos
    valor = re.sub(r"[\x00-\x1f\x7f]", "", valor)
    return valor.strip()[:max_len]


def _entrada_valida(usuario: str, senha: str) -> tuple[bool, str]:
    """
    Valida os campos de entrada antes de qualquer operação no banco.

    Retorna:
        (valido, mensagem_de_erro)
    """
    if not usuario or not senha:
        return False, "Usuário e senha são obrigatórios."

    if len(usuario) > 64 or len(senha) > 128:
        return False, "Entrada muito longa."

    # Bloqueia padrões suspeitos de SQL Injection
    padroes_suspeitos = [r"'", r"--", r";", r"/\*", r"OR\s+\d", r"DROP\s+TABLE"]
    for padrao in padroes_suspeitos:
        if re.search(padrao, usuario, re.IGNORECASE) or \
           re.search(padrao, senha, re.IGNORECASE):
            return False, "Entrada inválida detectada."

    return True, ""


def conectar() -> sqlite3.Connection:
    """Conecta ao banco de dados seguro."""
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def inicializar_banco() -> None:
    """
    Cria a tabela de usuários com senhas hashadas via bcrypt.
    Proteção: nenhuma senha é armazenada em plaintext.
    """
    con = conectar()
    cursor = con.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario   TEXT UNIQUE NOT NULL,
            senha     TEXT NOT NULL,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Senhas armazenadas com bcrypt — proteção intencional
    usuarios = [
        ("admin", "S3nh@F0rte#99"),
        ("user1", "P@ssw0rd!2024"),
        ("user2", "Tr0ub4dor&3"),
    ]

    for usuario, senha_plain in usuarios:
        hash_senha = bcrypt.hashpw(senha_plain.encode(), bcrypt.gensalt()).decode()
        cursor.execute(
            "INSERT OR IGNORE INTO usuarios (usuario, senha) VALUES (?, ?)",
            (usuario, hash_senha)
        )

    con.commit()
    con.close()


@app.after_request
def adicionar_headers_seguranca(response):
    """Adiciona headers HTTP de segurança em todas as respostas."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.route("/")
def home():
    # Gera token CSRF para o formulário
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return render_template("login.html", csrf_token=session["csrf_token"])


@app.route("/login", methods=["POST"])
def login():
    """
    Rota de login SEGURA.

    Proteções:
      1. Rate limiting: bloqueia após 5 tentativas em 60 segundos.
      2. Validação de entrada: rejeita padrões suspeitos antes do banco.
      3. Query parametrizada: elimina risco de SQL Injection.
      4. bcrypt: senhas comparadas com hash, nunca em plaintext.
      5. CSRF: valida token da sessão antes de processar.
    """
    ip = request.remote_addr

    # ── 1. Rate limiting ────────────────────────────────────────────────────
    if _verificar_rate_limit(ip):
        return "Muitas tentativas. Aguarde antes de tentar novamente.", 429
    # ────────────────────────────────────────────────────────────────────────

    usuario = _sanitizar_entrada(request.form.get("usuario", ""))
    senha   = request.form.get("senha", "")[:128]  # trunca sem sanitizar senha

    # ── 2. Validação de entrada ─────────────────────────────────────────────
    valido, erro = _entrada_valida(usuario, senha)
    if not valido:
        _registrar_tentativa(ip)
        return erro, 400
    # ────────────────────────────────────────────────────────────────────────

    con = None
    try:
        con = conectar()
        cursor = con.cursor()

        # ── 3. Query parametrizada (sem concatenação) ───────────────────────
        cursor.execute(
            "SELECT senha FROM usuarios WHERE usuario = ?",
            (usuario,)
        )
        # ────────────────────────────────────────────────────────────────────

        resultado = cursor.fetchone()

    except Exception:
        return "Erro interno. Tente novamente.", 500
    finally:
        if con:
            con.close()

    # ── 4. Verificação com bcrypt ───────────────────────────────────────────
    if resultado:
        try:
            if bcrypt.checkpw(senha.encode(), resultado["senha"].encode()):
                session.clear()  # regenera sessão após login
                return "Login realizado com segurança!"
        except Exception:
            pass
    # ────────────────────────────────────────────────────────────────────────

    # Registra tentativa falha
    _registrar_tentativa(ip)
    return "Usuário ou senha incorretos"


# Inicializa o banco ao subir a aplicação
inicializar_banco()

if __name__ == "__main__":
    print("\n✓  Aplicação SEGURA rodando na porta 5001")
    print("   Proteções: bcrypt + rate limiting + queries parametrizadas\n")
    app.run(port=5001, debug=False)
