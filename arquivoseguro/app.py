"""Himaya — aplicação SEGURA: cadastro e login."""

import os
import re
import secrets
from datetime import timedelta

from flask import Flask, jsonify, render_template, request, session
from werkzeug.middleware.proxy_fix import ProxyFix

import banco
from limitador import LimitadorTentativas
from validacao import (
    USUARIO_MAX, normalizar_email, validar_email, validar_senha,
)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    MAX_CONTENT_LENGTH=8 * 1024,
)
if os.environ.get("TRUST_PROXY") == "1":  # atrás de proxy (ex.: Render), para obter o IP real
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

limite_por_ip = LimitadorTentativas(limite=20, janela=60)
limite_por_conta = LimitadorTentativas(limite=5, janela=15 * 60)

MSG_LOGIN_INVALIDO = "E-mail ou senha inválidos."
_USUARIO_REGEX = re.compile(rf"^[\w.\-]{{3,{USUARIO_MAX}}}$")


def resposta(sucesso: bool, titulo: str, mensagem: str, status: int = 200, **extra):
    corpo = jsonify(sucesso=sucesso, titulo=titulo, mensagem=mensagem)
    corpo.status_code = status
    for chave, valor in extra.items():
        corpo.headers[chave] = valor
    return corpo


@app.after_request
def headers_seguranca(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    r.headers["Cache-Control"] = "no-store"
    return r


@app.route("/")
def home():
    return render_template("login.html")


@app.route("/cadastro", methods=["GET"])
def cadastro_form():
    return render_template("cadastro.html")


@app.route("/cadastro", methods=["POST"])
def cadastro():
    usuario = request.form.get("usuario", "").strip()
    email_bruto = request.form.get("email", "")
    senha = request.form.get("senha", "")
    confirmar = request.form.get("confirmar_senha", "")

    if not usuario or not email_bruto or not senha:
        return resposta(False, "Dados incompletos", "Preencha todos os campos.", 400)
    if not _USUARIO_REGEX.match(usuario):
        return resposta(False, "Usuário inválido",
                        f"Use de 3 a {USUARIO_MAX} caracteres: letras, números, ponto, hífen ou sublinhado.", 400)

    email, erro = validar_email(email_bruto)
    if erro:
        return resposta(False, "E-mail inválido", erro, 400)
    if senha != confirmar:
        return resposta(False, "Senhas diferentes", "Os dois campos de senha precisam ser iguais.", 400)
    erro = validar_senha(senha, email=email, usuario=usuario)
    if erro:
        return resposta(False, "Senha fraca", erro, 400)

    # Mensagem neutra: não revela se o conflito foi no e-mail ou no usuário.
    if not banco.criar_usuario(usuario, email, senha):
        return resposta(False, "Cadastro não concluído",
                        "Não foi possível concluir o cadastro com esses dados. "
                        "Se você já tem conta, faça login.", 409)

    return resposta(True, "Cadastro realizado", "Conta criada com sucesso. Agora você já pode entrar.", 201)


@app.route("/login", methods=["POST"])
def login():
    ip = request.remote_addr or "desconhecido"
    email = normalizar_email(request.form.get("email", ""))
    senha = request.form.get("senha", "")

    if limite_por_ip.bloqueado(ip) or limite_por_conta.bloqueado(email):
        return resposta(False, "Muitas tentativas",
                        "Muitas tentativas. Aguarde alguns minutos e tente novamente.",
                        429, **{"Retry-After": "900"})

    usuario = banco.buscar_por_email(email) if email and senha else None

    # Sempre executa um bcrypt, exista ou não a conta, para igualar o tempo de resposta.
    hash_alvo = usuario["senha"] if usuario else banco.HASH_FALSO
    senha_confere = banco.verificar_hash(senha, hash_alvo)

    if not (usuario and senha_confere):
        limite_por_ip.registrar_falha(ip)
        limite_por_conta.registrar_falha(email)
        return resposta(False, "Falha no login", MSG_LOGIN_INVALIDO, 401)

    limite_por_conta.limpar(email)
    session.clear()  # nova sessão após autenticar: evita session fixation
    session["user_id"] = usuario["id"]
    session.permanent = True
    return resposta(True, "Login realizado", f"Bem-vindo(a), {usuario['usuario']}.")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return resposta(True, "Sessão encerrada", "Você saiu da sua conta.")


banco.inicializar_banco()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5001)), debug=False)
