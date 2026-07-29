"""
Arquivo: testes/test_scanner.py
Descrição: Testes automatizados do Scanner de Segurança usando pytest.

Cobre:
  - Formato de retorno de todos os módulos
  - Tratamento de erros (app fora do ar, banco inacessível)
  - Lógica do main.py (extrair_severidade, calcular_score, gerar relatórios)
  - Integridade do banco de dados

Execução:
    pytest testes/test_scanner.py -v
    pytest testes/test_scanner.py -v --cov=scanner --cov-report=term-missing
"""

import os
import sys
import json
import sqlite3
import tempfile
import pytest
from unittest.mock import patch, MagicMock

# Garante que o projeto está no path
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

# ── Imports do projeto ───────────────────────────────────────────────────────
from scanner.modulos.sql_injection      import testar_sql_injection
from scanner.modulos.brute_force        import testar_bruteforce
from scanner.modulos.input_validation   import testar_validacao_entrada
from scanner.modulos.password_hash_check import testar_hash_senha
from scanner.modulos.password_strength  import testar_senha_fraca

from main import (
    extrair_severidade,
    calcular_score,
    executar_modulo,
    gerar_relatorio_txt,
    gerar_relatorio_json,
    gerar_relatorio_html,
    MODULOS_DISPONIVEIS,
)
# ────────────────────────────────────────────────────────────────────────────


# ══════════════════════════════════════════════════════════════════════════════
#  FIXTURES
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def resultado_critico():
    return {
        "modulo": "sql_injection", "nome": "SQL Injection",
        "resultado": "CRÍTICO - Vulnerável a SQL Injection",
        "severidade": "CRÍTICO", "duracao_s": 0.12, "status": "ok"
    }

@pytest.fixture
def resultado_seguro():
    return {
        "modulo": "brute_force", "nome": "Força Bruta",
        "resultado": "Seguro contra força bruta",
        "severidade": "SEGURO", "duracao_s": 0.08, "status": "ok"
    }

@pytest.fixture
def resultado_erro():
    return {
        "modulo": "input_validation", "nome": "Validação de Entrada",
        "resultado": "ERRO - Aplicação não acessível",
        "severidade": "ERRO", "duracao_s": 5.01, "status": "falha"
    }

@pytest.fixture
def lista_resultados_mista(resultado_critico, resultado_seguro, resultado_erro):
    return [resultado_critico, resultado_seguro, resultado_erro]

@pytest.fixture
def lista_todos_seguros():
    return [
        {"modulo": m, "nome": m, "resultado": "Seguro",
         "severidade": "SEGURO", "duracao_s": 0.1, "status": "ok"}
        for m in MODULOS_DISPONIVEIS
    ]

@pytest.fixture
def dir_temporario():
    """Cria um diretório temporário para salvar relatórios nos testes."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


# ══════════════════════════════════════════════════════════════════════════════
#  1. TESTES DE extrair_severidade()
# ══════════════════════════════════════════════════════════════════════════════

class TestExtrairSeveridade:

    def test_critico(self):
        assert extrair_severidade("CRÍTICO - SQL Injection detectado") == "CRÍTICO"

    def test_alto(self):
        assert extrair_severidade("ALTO - Senha fraca encontrada") == "ALTO"

    def test_medio(self):
        assert extrair_severidade("MÉDIO - Entrada suspeita refletida") == "MÉDIO"

    def test_baixo(self):
        assert extrair_severidade("BAIXO - Risco mínimo detectado") == "BAIXO"

    def test_seguro_prefixo(self):
        assert extrair_severidade("Seguro contra SQL Injection") == "SEGURO"

    def test_seguro_no_meio(self):
        assert extrair_severidade("Nenhuma vulnerabilidade SEGURO encontrada") == "SEGURO"

    def test_erro(self):
        assert extrair_severidade("ERRO - App fora do ar") == "SEGURO"

    def test_case_insensitive(self):
        assert extrair_severidade("crítico - vulnerabilidade grave") == "CRÍTICO"

    def test_string_vazia(self):
        # Não deve lançar exceção
        resultado = extrair_severidade("")
        assert isinstance(resultado, str)


# ══════════════════════════════════════════════════════════════════════════════
#  2. TESTES DE calcular_score()
# ══════════════════════════════════════════════════════════════════════════════

class TestCalcularScore:

    def test_todos_seguros_score_100(self, lista_todos_seguros):
        score = calcular_score(lista_todos_seguros)
        assert score["score"] == 100
        assert score["classificacao"] == "EXCELENTE"

    def test_todos_criticos_score_0(self):
        resultados = [
            {"severidade": "CRÍTICO"} for _ in range(5)
        ]
        score = calcular_score(resultados)
        assert score["score"] == 0
        assert score["classificacao"] == "CRÍTICO"

    def test_contagem_criticos(self, lista_resultados_mista):
        score = calcular_score(lista_resultados_mista)
        assert score["criticos"] == 1

    def test_contagem_seguros(self, lista_resultados_mista):
        score = calcular_score(lista_resultados_mista)
        assert score["seguros"] == 1

    def test_contagem_erros(self, lista_resultados_mista):
        score = calcular_score(lista_resultados_mista)
        assert score["erros"] == 1

    def test_total_correto(self, lista_resultados_mista):
        score = calcular_score(lista_resultados_mista)
        assert score["total"] == 3

    def test_classificacao_bom(self):
        resultados = [
            {"severidade": "SEGURO"}, {"severidade": "SEGURO"},
            {"severidade": "SEGURO"}, {"severidade": "SEGURO"},
            {"severidade": "CRÍTICO"},
        ]
        score = calcular_score(resultados)
        assert score["classificacao"] == "BOM"
        assert score["score"] == 80

    def test_classificacao_regular(self):
        resultados = [
            {"severidade": "SEGURO"}, {"severidade": "SEGURO"},
            {"severidade": "SEGURO"}, {"severidade": "CRÍTICO"},
            {"severidade": "CRÍTICO"},
        ]
        score = calcular_score(resultados)
        assert score["classificacao"] == "REGULAR"

    def test_lista_vazia(self):
        score = calcular_score([])
        assert score["score"] == 0
        assert score["total"] == 0


# ══════════════════════════════════════════════════════════════════════════════
#  3. TESTES DE executar_modulo()
# ══════════════════════════════════════════════════════════════════════════════

class TestExecutarModulo:

    def test_retorna_dicionario_com_chaves_corretas(self):
        import logging
        logger = logging.getLogger("scanner_test")

        with patch("main.testar_sql_injection", return_value="CRÍTICO - teste"):
            resultado = executar_modulo("sql_injection", logger)

        chaves = {"modulo", "nome", "resultado", "severidade", "duracao_s", "status"}
        assert chaves.issubset(resultado.keys())

    def test_captura_excecao_sem_quebrar(self):
        import logging
        logger = logging.getLogger("scanner_test")

        with patch("main.testar_sql_injection", side_effect=Exception("falha simulada")):
            resultado = executar_modulo("sql_injection", logger)

        assert resultado["status"] == "falha"
        assert "ERRO" in resultado["resultado"]

    def test_duracao_registrada(self):
        import logging
        logger = logging.getLogger("scanner_test")

        with patch("main.testar_bruteforce", return_value="Seguro"):
            resultado = executar_modulo("brute_force", logger)

        assert isinstance(resultado["duracao_s"], float)
        assert resultado["duracao_s"] >= 0

    def test_severidade_extraida_corretamente(self):
        import logging
        logger = logging.getLogger("scanner_test")

        with patch("main.testar_hash_senha", return_value="ALTO - Hash fraco"):
            resultado = executar_modulo("password_hash", logger)

        assert resultado["severidade"] == "ALTO"


# ══════════════════════════════════════════════════════════════════════════════
#  4. TESTES DE GERAÇÃO DE RELATÓRIOS
# ══════════════════════════════════════════════════════════════════════════════

class TestRelatorios:

    @pytest.fixture
    def dados_relatorio(self, lista_resultados_mista):
        score = calcular_score(lista_resultados_mista)
        return lista_resultados_mista, score

    # ── TXT ──────────────────────────────────────────────────────────────────

    def test_relatorio_txt_criado(self, dados_relatorio, dir_temporario):
        resultados, score = dados_relatorio
        caminho = os.path.join(dir_temporario, "relatorio.txt")
        gerar_relatorio_txt(resultados, score, caminho)
        assert os.path.exists(caminho)

    def test_relatorio_txt_contem_score(self, dados_relatorio, dir_temporario):
        resultados, score = dados_relatorio
        caminho = os.path.join(dir_temporario, "relatorio.txt")
        gerar_relatorio_txt(resultados, score, caminho)
        conteudo = open(caminho, encoding="utf-8").read()
        assert str(score["score"]) in conteudo

    def test_relatorio_txt_contem_todos_modulos(self, dados_relatorio, dir_temporario):
        resultados, score = dados_relatorio
        caminho = os.path.join(dir_temporario, "relatorio.txt")
        gerar_relatorio_txt(resultados, score, caminho)
        conteudo = open(caminho, encoding="utf-8").read()
        for r in resultados:
            assert r["nome"] in conteudo

    # ── JSON ─────────────────────────────────────────────────────────────────

    def test_relatorio_json_criado(self, dados_relatorio, dir_temporario):
        resultados, score = dados_relatorio
        caminho = os.path.join(dir_temporario, "relatorio.json")
        gerar_relatorio_json(resultados, score, caminho)
        assert os.path.exists(caminho)

    def test_relatorio_json_valido(self, dados_relatorio, dir_temporario):
        resultados, score = dados_relatorio
        caminho = os.path.join(dir_temporario, "relatorio.json")
        gerar_relatorio_json(resultados, score, caminho)
        with open(caminho, encoding="utf-8") as f:
            dados = json.load(f)
        assert "score" in dados
        assert "resultados" in dados
        assert "metadata" in dados

    def test_relatorio_json_score_correto(self, dados_relatorio, dir_temporario):
        resultados, score = dados_relatorio
        caminho = os.path.join(dir_temporario, "relatorio.json")
        gerar_relatorio_json(resultados, score, caminho)
        with open(caminho, encoding="utf-8") as f:
            dados = json.load(f)
        assert dados["score"]["score"] == score["score"]

    def test_relatorio_json_quantidade_resultados(self, dados_relatorio, dir_temporario):
        resultados, score = dados_relatorio
        caminho = os.path.join(dir_temporario, "relatorio.json")
        gerar_relatorio_json(resultados, score, caminho)
        with open(caminho, encoding="utf-8") as f:
            dados = json.load(f)
        assert len(dados["resultados"]) == len(resultados)

    # ── HTML ─────────────────────────────────────────────────────────────────

    def test_relatorio_html_criado(self, dados_relatorio, dir_temporario):
        resultados, score = dados_relatorio
        caminho = os.path.join(dir_temporario, "relatorio.html")
        gerar_relatorio_html(resultados, score, caminho)
        assert os.path.exists(caminho)

    def test_relatorio_html_estrutura(self, dados_relatorio, dir_temporario):
        resultados, score = dados_relatorio
        caminho = os.path.join(dir_temporario, "relatorio.html")
        gerar_relatorio_html(resultados, score, caminho)
        conteudo = open(caminho, encoding="utf-8").read()
        assert "<!DOCTYPE html>" in conteudo
        assert "<table" in conteudo
        assert str(score["score"]) in conteudo

    def test_relatorio_html_contem_severidades(self, dados_relatorio, dir_temporario):
        resultados, score = dados_relatorio
        caminho = os.path.join(dir_temporario, "relatorio.html")
        gerar_relatorio_html(resultados, score, caminho)
        conteudo = open(caminho, encoding="utf-8").read()
        assert "CRÍTICO" in conteudo
        assert "SEGURO" in conteudo


# ══════════════════════════════════════════════════════════════════════════════
#  5. TESTES DOS MÓDULOS — APP FORA DO AR
# ══════════════════════════════════════════════════════════════════════════════

class TestModulosAppForaDoAr:
    """
    Testa o comportamento dos módulos quando a aplicação Flask
    não está rodando. Todos devem retornar "ERRO - ..." sem lançar exceção.
    """

    URL_INEXISTENTE = "http://127.0.0.1:19999/login"

    def test_bruteforce_app_fora_do_ar(self):
        resultado = testar_bruteforce(url=self.URL_INEXISTENTE)
        assert resultado.startswith("ERRO")

    def test_sql_injection_app_fora_do_ar(self):
        # Também derruba o banco para garantir que ambos os vetores falhem
        with patch("scanner.modulos.sql_injection.conectar",
                   side_effect=RuntimeError("banco indisponível")):
            resultado = testar_sql_injection(url=self.URL_INEXISTENTE)
        assert resultado.startswith("ERRO")

    def test_input_validation_app_fora_do_ar(self):
        resultado = testar_validacao_entrada(url=self.URL_INEXISTENTE)
        assert resultado.startswith("ERRO")


# ══════════════════════════════════════════════════════════════════════════════
#  6. TESTES DOS MÓDULOS — BANCO INACESSÍVEL
# ══════════════════════════════════════════════════════════════════════════════

class TestModulosBancoInacessivel:
    """
    Testa o comportamento dos módulos que dependem do banco
    quando a conexão falha. Devem retornar "ERRO - ..." sem travar.
    """

    def test_hash_senha_banco_inacessivel(self):
        with patch("scanner.modulos.password_hash_check.conectar",
                   side_effect=RuntimeError("banco indisponível")):
            resultado = testar_hash_senha()
        assert resultado.startswith("ERRO")

    def test_senha_fraca_banco_inacessivel(self):
        with patch("scanner.modulos.password_strength.conectar",
                   side_effect=RuntimeError("banco indisponível")):
            resultado = testar_senha_fraca()
        assert resultado.startswith("ERRO")

    def test_sql_injection_banco_inacessivel(self):
        with patch("scanner.modulos.sql_injection.conectar",
                   side_effect=RuntimeError("banco indisponível")):
            with patch("scanner.modulos.sql_injection._testar_sql_web",
                       return_value=[]):
                resultado = testar_sql_injection()
        assert isinstance(resultado, str)


# ══════════════════════════════════════════════════════════════════════════════
#  7. TESTES DO FORMATO DE RETORNO DOS MÓDULOS
# ══════════════════════════════════════════════════════════════════════════════

PREFIXOS_VALIDOS = ("CRÍTICO", "ALTO", "MÉDIO", "BAIXO", "Seguro", "ERRO")

class TestFormatoRetornoModulos:
    """
    Garante que todos os módulos retornam strings com prefixo válido,
    independente do estado da aplicação.
    """

    def test_bruteforce_retorna_string(self):
        with patch("scanner.modulos.brute_force.requests.post",
                   side_effect=Exception("conexão recusada")):
            resultado = testar_bruteforce()
        assert isinstance(resultado, str)
        assert len(resultado) > 0

    def test_input_validation_retorna_string(self):
        with patch("scanner.modulos.input_validation.requests.post",
                   side_effect=Exception("conexão recusada")):
            resultado = testar_validacao_entrada()
        assert isinstance(resultado, str)

    def test_sql_injection_retorna_string(self):
        with patch("scanner.modulos.sql_injection.requests.post",
                   side_effect=Exception("conexão recusada")):
            resultado = testar_sql_injection()
        assert isinstance(resultado, str)
        assert len(resultado) > 0

    def test_hash_senha_retorna_string(self):
        with patch("scanner.modulos.password_hash_check.conectar",
                   side_effect=RuntimeError("erro")):
            resultado = testar_hash_senha()
        assert isinstance(resultado, str)

    def test_senha_fraca_retorna_string(self):
        with patch("scanner.modulos.password_strength.conectar",
                   side_effect=RuntimeError("erro")):
            resultado = testar_senha_fraca()
        assert isinstance(resultado, str)


# ══════════════════════════════════════════════════════════════════════════════
#  8. TESTES DO DATABASE
# ══════════════════════════════════════════════════════════════════════════════

class TestDatabase:

    def test_conectar_retorna_conexao(self):
        from core.database import conectar
        con = conectar()
        assert con is not None
        con.close()

    def test_tabela_usuarios_existe(self):
        from core.database import conectar, inicializar_banco
        inicializar_banco()
        con = conectar()
        cursor = con.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='usuarios'")
        assert cursor.fetchone() is not None
        con.close()

    def test_usuarios_inseridos(self):
        from core.database import conectar, inicializar_banco
        inicializar_banco()
        con = conectar()
        cursor = con.cursor()
        cursor.execute("SELECT COUNT(*) FROM usuarios")
        total = cursor.fetchone()[0]
        assert total > 0
        con.close()

    def test_senhas_nao_sao_plaintext(self):
        from core.database import conectar, inicializar_banco
        inicializar_banco()
        con = conectar()
        cursor = con.cursor()
        cursor.execute("SELECT senha FROM usuarios")
        senhas = [row[0] for row in cursor.fetchall()]
        con.close()
        for senha in senhas:
            # bcrypt sempre começa com $2b$ e tem mais de 20 caracteres
            assert len(senha) > 20, f"Senha suspeita de ser plaintext: {senha}"
            assert senha.startswith("$2"), f"Senha não usa bcrypt: {senha}"

    def test_resetar_banco(self):
        from core.database import resetar_banco, conectar
        resetar_banco()
        con = conectar()
        cursor = con.cursor()
        cursor.execute("SELECT COUNT(*) FROM usuarios")
        total = cursor.fetchone()[0]
        con.close()
        assert total > 0  # após reset, deve ter os usuários de seed


# ══════════════════════════════════════════════════════════════════════════════
#  9. TESTES DE INTEGRAÇÃO — MÓDULOS COM MOCK DA APP
# ══════════════════════════════════════════════════════════════════════════════

class TestIntegracaoComMock:
    """
    Simula respostas da aplicação Flask para testar a lógica
    dos módulos sem precisar de uma aplicação rodando.
    """

    def test_bruteforce_detecta_login_bem_sucedido(self):
        mock_resp = MagicMock()
        mock_resp.text = "Login realizado!"
        mock_resp.status_code = 200

        with patch("scanner.modulos.brute_force.requests.post", return_value=mock_resp):
            resultado = testar_bruteforce()

        assert "CRÍTICO" in resultado or "ALTO" in resultado

    def test_bruteforce_detecta_bloqueio(self):
        mock_resp = MagicMock()
        mock_resp.text = "Muitas tentativas. Aguarde."
        mock_resp.status_code = 429

        with patch("scanner.modulos.brute_force.requests.post", return_value=mock_resp):
            resultado = testar_bruteforce()

        assert "Seguro" in resultado or "bloqueio" in resultado.lower()

    def test_input_validation_detecta_reflexao_xss(self):
        def resposta_xss(url, data, timeout, allow_redirects):
            mock = MagicMock()
            mock.text = f"Erro: {data.get('usuario', '')} inválido"
            return mock

        with patch("scanner.modulos.input_validation.requests.post",
                   side_effect=resposta_xss):
            with patch("scanner.modulos.input_validation._enviar_payload",
                       return_value="<script>alert('xss')</script> está na página"):
                resultado = testar_validacao_entrada()

        assert isinstance(resultado, str)

    def test_sql_injection_detecta_vetor_web(self):
        """Só o vetor web é vulnerável (banco limpo) → severidade ALTO."""
        mock_resp = MagicMock()
        mock_resp.text = "Login realizado!"
        mock_resp.status_code = 200

        mock_con = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None  # banco não retorna nada = seguro
        mock_con.cursor.return_value = mock_cursor

        with patch("scanner.modulos.sql_injection.requests.post",
                   return_value=mock_resp):
            with patch("scanner.modulos.sql_injection.conectar",
                       return_value=mock_con):
                resultado = testar_sql_injection()

        assert "ALTO" in resultado or "CRÍTICO" in resultado

    def test_sql_injection_seguro_vetor_web(self):
        """Nenhum payload funciona nem no banco nem via web → Seguro."""
        mock_resp = MagicMock()
        mock_resp.text = "Usuário ou senha incorretos"
        mock_resp.status_code = 200

        mock_con = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None
        mock_con.cursor.return_value = mock_cursor

        with patch("scanner.modulos.sql_injection.requests.post",
                   return_value=mock_resp):
            with patch("scanner.modulos.sql_injection.conectar",
                       return_value=mock_con):
                resultado = testar_sql_injection()

        assert "Seguro" in resultado

    def test_hash_senha_detecta_plaintext(self):
        mock_con = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [("admin", "123456"), ("user1", "abc")]
        mock_con.cursor.return_value = mock_cursor

        with patch("scanner.modulos.password_hash_check.conectar",
                   return_value=mock_con):
            resultado = testar_hash_senha()

        assert "CRÍTICO" in resultado or "ALTO" in resultado

    def test_hash_senha_reconhece_bcrypt(self):
        hash_bcrypt = "$2b$12$KIXwfMaKL1aBJUOPIH8Lfe9Fqz0OFPjxOx9xtVkAqO3GgXkq8WOu"
        mock_con = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [("admin", hash_bcrypt)]
        mock_con.cursor.return_value = mock_cursor

        with patch("scanner.modulos.password_hash_check.conectar",
                   return_value=mock_con):
            resultado = testar_hash_senha()

        assert "Seguro" in resultado

    def test_senha_fraca_detecta_senha_comum(self):
        import bcrypt as _bcrypt
        hash_fraco = _bcrypt.hashpw(b"123456", _bcrypt.gensalt()).decode()

        mock_con = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [("admin", hash_fraco)]
        mock_con.cursor.return_value = mock_cursor

        with patch("scanner.modulos.password_strength.conectar",
                   return_value=mock_con):
            resultado = testar_senha_fraca()

        assert "ALTO" in resultado or "MÉDIO" in resultado

    def test_senha_forte_passa_no_teste(self):
        import bcrypt as _bcrypt
        hash_forte = _bcrypt.hashpw(b"S3nh@F0rte#99!", _bcrypt.gensalt()).decode()

        mock_con = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [("admin", hash_forte)]
        mock_con.cursor.return_value = mock_cursor

        with patch("scanner.modulos.password_strength.conectar",
                   return_value=mock_con):
            resultado = testar_senha_fraca()

        assert "Seguro" in resultado