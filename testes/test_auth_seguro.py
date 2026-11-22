import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "arquivoseguro"))
os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "teste.db")
os.environ["COOKIE_SECURE"] = "0"

import app as app_seguro  # noqa: E402
from limitador import LimitadorTentativas  # noqa: E402
from validacao import validar_senha  # noqa: E402

VALIDO = {"usuario": "maria", "email": "Maria@Exemplo.com", "senha": "Xv9#kLm!pQ2z", "confirmar_senha": "Xv9#kLm!pQ2z"}


@pytest.fixture()
def client():
    app_seguro.limite_por_ip = LimitadorTentativas(20, 60)
    app_seguro.limite_por_conta = LimitadorTentativas(5, 900)
    return app_seguro.app.test_client()


@pytest.mark.parametrize("senha", [
    "123456", "Ab1!", "senhasemmaiuscula1!", "SENHASEMMINUSCULA1!", "SemNumero!!x",
    "SemEspecial123", "Abcd1234!", "Aaa1!zzzzz", "P@ssw0rd", "Qwerty123!", "Maria#1x9",
])
def test_senhas_rejeitadas(senha):
    assert validar_senha(senha, email="maria@x.com", usuario="maria")


def test_senha_forte_aceita():
    assert validar_senha("Xv9#kLm!pQ2z") == ""


def test_cadastro_e_login_ok(client):
    assert client.post("/cadastro", data=VALIDO).status_code == 201
    r = client.post("/login", data={"email": "maria@exemplo.com", "senha": VALIDO["senha"]})
    assert r.status_code == 200
    with client.session_transaction() as s:
        assert "user_id" in s


def test_senha_nao_fica_em_texto_plano(client):
    client.post("/cadastro", data={**VALIDO, "usuario": "joao", "email": "joao@exemplo.com"})
    linha = app_seguro.banco.buscar_por_email("joao@exemplo.com")
    assert linha["senha"].startswith("$2") and VALIDO["senha"] not in linha["senha"]


@pytest.mark.parametrize("email", ["abc", "a@b", "a b@c.com", "@x.com", "a@@x.com"])
def test_email_invalido(client, email):
    assert client.post("/cadastro", data={**VALIDO, "email": email}).status_code == 400


def test_cadastro_duplicado_mensagem_neutra(client):
    client.post("/cadastro", data={**VALIDO, "usuario": "ana", "email": "ana@exemplo.com"})
    r1 = client.post("/cadastro", data={**VALIDO, "usuario": "ana", "email": "outro@exemplo.com"})
    r2 = client.post("/cadastro", data={**VALIDO, "usuario": "outra", "email": "ana@exemplo.com"})
    assert r1.status_code == r2.status_code == 409
    assert r1.get_json() == r2.get_json()


def test_login_mensagem_generica(client):
    client.post("/cadastro", data={**VALIDO, "usuario": "bia", "email": "bia@exemplo.com"})
    errada = client.post("/login", data={"email": "bia@exemplo.com", "senha": "Errada#123x"})
    inexistente = client.post("/login", data={"email": "naoexiste@exemplo.com", "senha": "Errada#123x"})
    assert errada.status_code == inexistente.status_code == 401
    assert errada.get_json() == inexistente.get_json()


def test_sql_injection_no_login(client):
    for payload in ("' OR '1'='1", "admin@seguro.local' --", "x'; DROP TABLE usuarios;--"):
        r = client.post("/login", data={"email": payload, "senha": payload})
        assert r.status_code == 401
    assert app_seguro.banco.buscar_por_email("admin@seguro.local")


def test_forca_bruta_bloqueia_conta(client):
    for _ in range(5):
        client.post("/login", data={"email": "admin@seguro.local", "senha": "Errada#123x"})
    r = client.post("/login", data={"email": "admin@seguro.local", "senha": "S3nh@F0rte#99"})
    assert r.status_code == 429 and "Retry-After" in r.headers


def test_cookie_de_sessao_flags(client):
    client.post("/login", data={"email": "user2@seguro.local", "senha": "Tr0ub4dor&3"})
    cookie = client.get_cookie("session")
    assert cookie.http_only and cookie.same_site == "Lax"
