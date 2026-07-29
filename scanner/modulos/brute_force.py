"""
Módulo: Teste de Força Bruta
Descrição: Tenta autenticação com wordlist expandida contra múltiplos
           usuários, conta tentativas e detecta se a aplicação bloqueia
           requisições após N falhas (proteção anti-brute-force).
"""

import sys
import os
import requests

# Sobe DOIS níveis (scanner/modulos -> raiz do projeto)
pasta_raiz = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, pasta_raiz)

from config import URL_ALVO

# Top 30 senhas mais comuns (OWASP / SecLists)
WORDLIST = [
    "123456", "password", "123456789", "12345678", "12345",
    "1234567", "qwerty", "abc123", "football", "monkey",
    "letmein", "111111", "mustang", "access", "shadow",
    "master", "michael", "superman", "696969", "123123",
    "batman", "trustno1", "dragon", "passw0rd", "iloveyou",
    "admin", "admin123", "senha", "1234", "123",
]

# Usuários comuns para testar
USUARIOS_ALVO = ["admin", "administrador", "root", "user", "teste"]

# Indicadores de sucesso na resposta
INDICADORES_SUCESSO = [
    "login realizado",
    "bem-vindo",
    "dashboard",
    "logout",
    "sucesso",
]

# Indicadores de bloqueio
INDICADORES_BLOQUEIO = [
    "bloqueado",
    "too many",
    "muitas tentativas",
    "aguarde",
    "tente novamente",
    "rate limit",
    "locked",
]


def _autenticacao_bem_sucedida(resposta_html: str) -> bool:
    """Verifica se a resposta indica login bem-sucedido."""
    texto = resposta_html.lower()
    return any(ind in texto for ind in INDICADORES_SUCESSO)


def _acesso_bloqueado(resposta_html: str, status_code: int) -> bool:
    """Verifica se a aplicação está bloqueando as requisições."""
    if status_code in (429, 403):
        return True
    texto = resposta_html.lower()
    return any(ind in texto for ind in INDICADORES_BLOQUEIO)


def testar_bruteforce(url: str = URL_ALVO) -> str:
    """
    Realiza teste de força bruta contra a aplicação web.

    Retorna:
        str com prefixo de severidade, credenciais encontradas (se houver)
        e informações sobre proteção anti-brute-force detectada.
    """
    tentativas_total = 0
    credenciais_encontradas = []
    bloqueio_detectado = False

    for usuario in USUARIOS_ALVO:
        for senha in WORDLIST:
            try:
                resposta = requests.post(
                    url,
                    data={"usuario": usuario, "senha": senha},
                    timeout=60,
                    allow_redirects=True,
                )
            except requests.exceptions.ConnectionError:
                return f"ERRO - Aplicação não está acessível em {url}"
            except requests.exceptions.Timeout:
                return f"ERRO - Timeout ao conectar em {url}"

            tentativas_total += 1

            # Detecta bloqueio
            if _acesso_bloqueado(resposta.text, resposta.status_code):
                bloqueio_detectado = True
                break

            # Detecta login bem-sucedido
            if _autenticacao_bem_sucedida(resposta.text):
                credenciais_encontradas.append((usuario, senha))
                break  # Encontrou para este usuário, passa para o próximo

        if bloqueio_detectado:
            break

    # Monta resultado
    if bloqueio_detectado and not credenciais_encontradas:
        return (
            f"Seguro — aplicação bloqueou requisições após {tentativas_total} "
            f"tentativa(s) (proteção anti-brute-force ativa)"
        )

    if not credenciais_encontradas:
        protecao = " (sem bloqueio detectado)" if not bloqueio_detectado else ""
        return (
            f"Seguro — nenhuma credencial encontrada após "
            f"{tentativas_total} tentativa(s){protecao}"
        )

    # Há credenciais encontradas — classifica severidade
    nivel = "CRÍTICO" if any(u in ("admin", "root") for u, _ in credenciais_encontradas) else "ALTO"
    creds_str = ", ".join(f"{u}:{s}" for u, s in credenciais_encontradas)
    aviso_bloqueio = " (bloqueio parcial detectado)" if bloqueio_detectado else " (sem proteção detectada)"

    return (
        f"{nivel} - Credencial(is) encontrada(s) após {tentativas_total} tentativa(s){aviso_bloqueio}. "
        f"Credenciais: {creds_str}"
    )


if __name__ == "__main__":
    print(testar_bruteforce())
