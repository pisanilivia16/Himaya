"""
Módulo: Validação de Entrada
Descrição: Envia payloads maliciosos reais para a aplicação e verifica
           se a resposta reflete o conteúdo (XSS, path traversal, injeção).
"""

import sys
import os
import requests

pasta_raiz = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, pasta_raiz)

from config import URL_ALVO

# Payloads organizados por categoria e severidade
PAYLOADS = [
    # (payload, categoria, severidade_se_refletido)
    ("<script>alert('xss')</script>",   "XSS",            "CRÍTICO"),
    ("<img src=x onerror=alert(1)>",    "XSS",            "CRÍTICO"),
    ("' OR '1'='1",                     "SQL Injection",  "CRÍTICO"),
    ("' OR 1=1--",                      "SQL Injection",  "CRÍTICO"),
    ("admin' --",                        "SQL Injection",  "ALTO"),
    ("../../../etc/passwd",             "Path Traversal", "ALTO"),
    ("../../windows/system32",          "Path Traversal", "ALTO"),
    ("; DROP TABLE usuarios",           "SQL Injection",  "ALTO"),
    ("${7*7}",                          "Template Inj.",  "MÉDIO"),
    ("{{7*7}}",                         "Template Inj.",  "MÉDIO"),
    ("--",                              "Comentário SQL", "MÉDIO"),
]


def _enviar_payload(url: str, campo: str, payload: str) -> str | None:
    """Envia um payload em um campo do formulário e retorna o corpo da resposta."""
    try:
        dados = {"usuario": "admin", "senha": "qualquer"}
        dados[campo] = payload
        resposta = requests.post(url, data=dados, timeout=5)
        return resposta.text
    except requests.exceptions.ConnectionError:
        return None
    except requests.exceptions.Timeout:
        return None


def _payload_refletido(resposta_html: str, payload: str) -> bool:
    """Verifica se o payload aparece literalmente na resposta (reflexão direta)."""
    return payload.lower() in resposta_html.lower()


def testar_validacao_entrada(url: str = URL_ALVO) -> str:
    """
    Testa validação de entrada enviando payloads reais para a aplicação.

    Retorna:
        str com prefixo de severidade (CRÍTICO / ALTO / MÉDIO / Seguro)
        e detalhes do payload que foi refletido.
    """
    # Verifica se a aplicação está no ar
    teste = _enviar_payload(url, "usuario", "teste")
    if teste is None:
        return f"ERRO - Aplicação não acessível em {url}"

    encontrados = []  # [(severidade, categoria, payload, campo)]

    for payload, categoria, severidade in PAYLOADS:
        # Testa nos dois campos principais
        for campo in ("usuario", "senha"):
            resposta = _enviar_payload(url, campo, payload)
            if resposta and _payload_refletido(resposta, payload):
                encontrados.append((severidade, categoria, payload, campo))
                break  # Basta achar em um campo por payload

    if not encontrados:
        return "Seguro — nenhuma entrada maliciosa foi refletida pela aplicação"

    # Determina a pior severidade encontrada
    ordem = {"CRÍTICO": 3, "ALTO": 2, "MÉDIO": 1}
    pior = max(encontrados, key=lambda x: ordem.get(x[0], 0))
    severidade_final, categoria, payload, campo = pior

    total = len(encontrados)
    return (
        f"{severidade_final} - {total} payload(s) refletido(s). "
        f"Pior caso: [{categoria}] campo='{campo}' payload='{payload[:40]}'"
    )


if __name__ == "__main__":
    print(testar_validacao_entrada())
