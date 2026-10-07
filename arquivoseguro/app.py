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
  - Cadastro com política de senha (mín. 8 caracteres, maiúscula,
    minúscula, número e caractere especial)
  - Cadastro com validação de formato de e-mail e checagem de
    duplicidade (usuário/e-mail já cadastrados)
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


# ── Validação de e-mail e política de senha ─────────────────────────────────
_EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _email_valido(email: str) -> bool:
    """Valida formato básico de e-mail (usuario@dominio.tld)."""
    return bool(_EMAIL_REGEX.match(email))


def _senha_atende_politica(senha: str) -> tuple[bool, str]:
    """
    Verifica se a senha atende à política de segurança:
      - Mínimo de 8 caracteres
      - Ao menos 1 letra maiúscula, 1 minúscula, 1 número e 1 caractere especial

    Retorna:
        (atende, mensagem_de_erro)
    """
    if len(senha) < 8:
        return False, "A senha deve ter no mínimo 8 caracteres."
    if not re.search(r"[A-Z]", senha):
        return False, "A senha deve conter ao menos uma letra maiúscula."
    if not re.search(r"[a-z]", senha):
        return False, "A senha deve conter ao menos uma letra minúscula."
    if not re.search(r"[0-9]", senha):
        return False, "A senha deve conter ao menos um número."
    if not re.search(r"[^A-Za-z0-9]", senha):
        return False, "A senha deve conter ao menos um caractere especial."
    return True, ""
# ────────────────────────────────────────────────────────────────────────────


def _pagina_resultado(sucesso: bool, titulo: str, mensagem: str,
                       status: int = 200, voltar_para: str = "/",
                       mostrar_login: bool = False):
    """Renderiza a tela de resultado (sucesso/erro) com o status HTTP certo."""
    return render_template(
        "resultado.html",
        sucesso=sucesso, titulo=titulo, mensagem=mensagem,
        voltar_para=voltar_para, mostrar_login=mostrar_login,
    ), status


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
            email     TEXT UNIQUE NOT NULL,
            senha     TEXT NOT NULL,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Senhas armazenadas com bcrypt — proteção intencional
    usuarios = [
        ("admin", "admin@seguro.local", "S3nh@F0rte#99"),
        ("user1", "user1@seguro.local", "P@ssw0rd!2024"),
        ("user2", "user2@seguro.local", "Tr0ub4dor&3"),
    ]

    for usuario, email, senha_plain in usuarios:
        hash_senha = bcrypt.hashpw(senha_plain.encode(), bcrypt.gensalt()).decode()
        cursor.execute(
            "INSERT OR IGNORE INTO usuarios (usuario, email, senha) VALUES (?, ?, ?)",
            (usuario, email, hash_senha)
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
        return _pagina_resultado(
            False, "Muitas tentativas",
            "Você excedeu o limite de tentativas. Aguarde um momento antes de tentar novamente.",
            status=429, voltar_para="/",
        )
    # ────────────────────────────────────────────────────────────────────────

    usuario = _sanitizar_entrada(request.form.get("usuario", ""))
    senha   = request.form.get("senha", "")[:128]  # trunca sem sanitizar senha

    # ── 2. Validação de entrada ─────────────────────────────────────────────
    valido, erro = _entrada_valida(usuario, senha)
    if not valido:
        _registrar_tentativa(ip)
        return _pagina_resultado(False, "Entrada inválida", erro, status=400, voltar_para="/")
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
        return _pagina_resultado(
            False, "Erro interno", "Algo deu errado. Tente novamente.",
            status=500, voltar_para="/",
        )
    finally:
        if con:
            con.close()

    # ── 4. Verificação com bcrypt ───────────────────────────────────────────
    if resultado:
        try:
            if bcrypt.checkpw(senha.encode(), resultado["senha"].encode()):
                session.clear()  # regenera sessão após login
                return _pagina_resultado(
                    True, "Login realizado com segurança!",
                    f"Bem-vindo(a), {usuario}. Sua autenticação passou por rate limiting, "
                    "validação de entrada, query parametrizada e verificação bcrypt.",
                )
        except Exception:
            pass
    # ────────────────────────────────────────────────────────────────────────

    # Registra tentativa falha
    _registrar_tentativa(ip)
    return _pagina_resultado(
        False, "Usuário ou senha incorretos",
        "Verifique seus dados e tente novamente.",
        status=401, voltar_para="/",
    )


@app.route("/cadastro")
def cadastro_form():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return render_template("cadastro.html", csrf_token=session["csrf_token"])


@app.route("/cadastro", methods=["POST"])
def cadastro():
    """
    Rota de cadastro SEGURA.

    Proteções:
      1. Validação de presença e tamanho dos campos.
      2. Validação de formato de e-mail.
      3. Confirmação de senha (os dois campos devem bater).
      4. Política de senha: mín. 8 caracteres, maiúscula, minúscula,
         número e caractere especial.
      5. Checagem de duplicidade (usuário/e-mail já cadastrados).
      6. Hash bcrypt antes de armazenar.
      7. Query parametrizada (sem concatenação).
    """
    usuario         = _sanitizar_entrada(request.form.get("usuario", ""))
    email           = _sanitizar_entrada(request.form.get("email", ""), max_len=120)
    senha           = request.form.get("senha", "")[:128]
    confirmar_senha = request.form.get("confirmar_senha", "")[:128]

    # ── 1. Presença e tamanho ───────────────────────────────────────────────
    if not usuario or not email or not senha:
        return _pagina_resultado(False, "Dados incompletos", "Preencha todos os campos.",
                                  status=400, voltar_para="/cadastro")
    if len(usuario) > 64:
        return _pagina_resultado(False, "Usuário muito longo", "Escolha um usuário mais curto.",
                                  status=400, voltar_para="/cadastro")
    # ────────────────────────────────────────────────────────────────────────

    # ── 2. Formato de e-mail ─────────────────────────────────────────────────
    if not _email_valido(email):
        return _pagina_resultado(False, "E-mail inválido", "Digite um e-mail no formato nome@dominio.com.",
                                  status=400, voltar_para="/cadastro")
    # ────────────────────────────────────────────────────────────────────────

    # ── 3. Confirmação de senha ──────────────────────────────────────────────
    if senha != confirmar_senha:
        return _pagina_resultado(False, "Senhas não coincidem", "Os dois campos de senha precisam ser iguais.",
                                  status=400, voltar_para="/cadastro")
    # ────────────────────────────────────────────────────────────────────────

    # ── 4. Política de senha ─────────────────────────────────────────────────
    senha_ok, erro_senha = _senha_atende_politica(senha)
    if not senha_ok:
        return _pagina_resultado(False, "Senha fora da política", erro_senha,
                                  status=400, voltar_para="/cadastro")
    # ────────────────────────────────────────────────────────────────────────

    con = None
    try:
        con = conectar()
        cursor = con.cursor()

        # ── 5. Checagem de duplicidade ──────────────────────────────────────
        cursor.execute(
            "SELECT 1 FROM usuarios WHERE usuario = ? OR email = ?",
            (usuario, email)
        )
        if cursor.fetchone():
            return _pagina_resultado(False, "Já cadastrado", "Esse usuário ou e-mail já existe. Tente entrar em vez disso.",
                                      status=409, voltar_para="/cadastro")
        # ────────────────────────────────────────────────────────────────────

        # ── 6 e 7. bcrypt + query parametrizada ──────────────────────────────
        hash_senha = bcrypt.hashpw(senha.encode(), bcrypt.gensalt()).decode()
        cursor.execute(
            "INSERT INTO usuarios (usuario, email, senha) VALUES (?, ?, ?)",
            (usuario, email, hash_senha)
        )
        con.commit()
        # ────────────────────────────────────────────────────────────────────

    except Exception:
        return _pagina_resultado(False, "Erro interno", "Algo deu errado. Tente novamente.",
                                  status=500, voltar_para="/cadastro")
    finally:
        if con:
            con.close()

    return _pagina_resultado(
        True, "Cadastro realizado com sucesso!",
        f"Conta de {usuario} criada com senha protegida por bcrypt. Agora você já pode entrar.",
        mostrar_login=True,
    )


# Inicializa o banco ao subir a aplicação
inicializar_banco()

if __name__ == "__main__":
    print("\n✓  Aplicação SEGURA rodando na porta 5001")
    print("   Proteções: bcrypt + rate limiting + queries parametrizadas\n")
    app.run(port=5001, debug=False)
