"""
Módulo: SQL Injection
Descrição: Testa vulnerabilidades de SQL Injection tanto diretamente
           no banco de dados quanto via requisição HTTP, unificando
           os dois vetores (banco + web) em um único módulo.
"""

import sys
import os
import requests

pasta_raiz = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, pasta_raiz)

from core.database import conectar
from config import URL_ALVO

# Payloads clássicos de SQL Injection (OWASP)
PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 'a'='a",
    "' OR 1=1#",
    "' OR '1'='1'--",
    "admin'--",
    "' OR 1=1/*",
    "') OR ('1'='1",
]

# Indicadores de sucesso na resposta web
INDICADORES_SUCESSO = [
    "login realizado",
    "bem-vindo",
    "dashboard",
    "logout",
    "sucesso",
]


def _testar_sql_banco(payloads: list[str]) -> list[str]:
    """
    Testa SQL Injection diretamente no banco usando queries concatenadas
    e verifica se retornam resultados indevidos.

    Retorna lista de payloads que exploram a vulnerabilidade.
    """
    con = None
    vulneraveis = []

    try:
        con = conectar()
        cursor = con.cursor()

        for payload in payloads:
            try:
                # Query vulnerável proposital — simula código legado sem parametrização
                query = f"SELECT * FROM usuarios WHERE usuario='admin' AND senha='{payload}'"
                cursor.execute(query)
                if cursor.fetchone():
                    vulneraveis.append(payload)
            except Exception:
                # Erro de SQL também pode indicar injeção — registra como suspeito
                vulneraveis.append(f"{payload} (causou erro SQL)")

    except Exception as e:
        return [f"ERRO_BANCO:{e}"]
    finally:
        if con:
            con.close()

    return vulneraveis


def _testar_sql_web(url: str, payloads: list[str]) -> list[str]:
    """
    Testa SQL Injection via HTTP POST contra o endpoint de login.

    Retorna lista de payloads que exploram a vulnerabilidade.
    """
    vulneraveis = []

    for payload in payloads:
        try:
            resposta = requests.post(
                url,
                data={"usuario": "admin", "senha": payload},
                timeout=5,
                allow_redirects=True,
            )
        except requests.exceptions.ConnectionError:
            return [f"ERRO_WEB:conexão recusada em {url}"]
        except requests.exceptions.Timeout:
            return [f"ERRO_WEB:timeout em {url}"]

        texto = resposta.text.lower()
        if any(ind in texto for ind in INDICADORES_SUCESSO):
            vulneraveis.append(payload)

    return vulneraveis


def testar_sql_injection(url: str = URL_ALVO) -> str:
    """
    Executa testes de SQL Injection no banco e na camada web.

    Retorna:
        str com prefixo de severidade, vetor de ataque (banco/web/ambos)
        e exemplo de payload que funcionou.
    """
    vuln_banco = _testar_sql_banco(PAYLOADS)
    vuln_web   = _testar_sql_web(url, PAYLOADS)

    # Trata erros de infraestrutura
    erro_banco = any(p.startswith("ERRO_BANCO:") for p in vuln_banco)
    erro_web   = any(p.startswith("ERRO_WEB:")   for p in vuln_web)

    if erro_banco and erro_web:
        return "ERRO - Não foi possível testar SQL Injection (banco e web inacessíveis)"

    # Filtra payloads reais (sem as mensagens de erro)
    vuln_banco_real = [p for p in vuln_banco if not p.startswith("ERRO_BANCO:")]
    vuln_web_real   = [p for p in vuln_web   if not p.startswith("ERRO_WEB:")]

    ambos_seguros = not vuln_banco_real and not vuln_web_real
    if ambos_seguros:
        vetores_ok = []
        if not erro_banco: vetores_ok.append("banco")
        if not erro_web:   vetores_ok.append("web")
        return f"Seguro contra SQL Injection ({', '.join(vetores_ok)} testado(s))"

    # Monta detalhe dos vetores vulneráveis
    detalhes = []
    if vuln_banco_real:
        exemplo = vuln_banco_real[0][:50]
        detalhes.append(f"banco ({len(vuln_banco_real)} payload(s), ex: '{exemplo}')")
    if vuln_web_real:
        exemplo = vuln_web_real[0][:50]
        detalhes.append(f"web ({len(vuln_web_real)} payload(s), ex: '{exemplo}')")

    # Severidade: CRÍTICO se ambos os vetores vulneráveis, ALTO se apenas um
    nivel = "CRÍTICO" if (vuln_banco_real and vuln_web_real) else "ALTO"
    vetor_str = " e ".join(detalhes)

    return f"{nivel} - SQL Injection detectado via {vetor_str}"


if __name__ == "__main__":
    print(testar_sql_injection())
