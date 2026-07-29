"""
Módulo: Verificação de Hash de Senha
Descrição: Analisa como as senhas estão armazenadas no banco,
           identifica o algoritmo usado e classifica o nível de segurança.
"""

import sys
import os
import re

pasta_raiz = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, pasta_raiz)

from core.database import conectar


# Padrões conhecidos de algoritmos de hash
PADROES_HASH = [
    # (regex, algoritmo, seguro)
    (r"^\$2[aby]\$\d{2}\$.{53}$",          "bcrypt",          True),
    (r"^\$argon2(i|d|id)\$",               "argon2",          True),
    (r"^\$pbkdf2-sha(256|512)\$",          "pbkdf2",          True),
    (r"^[a-f0-9]{128}$",                   "sha-512 (hex)",   False),  # sem salt
    (r"^[a-f0-9]{64}$",                    "sha-256 (hex)",   False),  # sem salt
    (r"^[a-f0-9]{40}$",                    "sha-1 (hex)",     False),  # fraco
    (r"^[a-f0-9]{32}$",                    "md5 (hex)",       False),  # fraco
    (r"^\$1\$",                            "md5crypt",        False),  # fraco
    (r"^\$5\$",                            "sha-256crypt",    False),  # sem sal moderno
    (r"^\$6\$",                            "sha-512crypt",    False),  # sem sal moderno
]


def _identificar_algoritmo(valor: str) -> tuple[str, bool]:
    """
    Tenta identificar o algoritmo de hash pelo formato da string.

    Retorna:
        (nome_algoritmo, é_seguro)
    """
    for padrao, nome, seguro in PADROES_HASH:
        if re.match(padrao, valor, re.IGNORECASE):
            return nome, seguro

    # Heurística: se for curto demais, provavelmente é plaintext
    if len(valor) < 20:
        return "plaintext (sem hash)", False

    # Comprimento razoável mas formato desconhecido
    return "formato desconhecido", False


def testar_hash_senha() -> str:
    """
    Verifica como as senhas estão armazenadas no banco de dados.

    Retorna:
        str com prefixo de severidade e detalhes do algoritmo encontrado.
    """
    con = None
    try:
        con = conectar()
        cursor = con.cursor()
        cursor.execute("SELECT usuario, senha FROM usuarios")
        registros = cursor.fetchall()
    except Exception as e:
        return f"ERRO - Não foi possível acessar o banco: {e}"
    finally:
        if con:
            con.close()

    if not registros:
        return "ERRO - Nenhum usuário encontrado no banco de dados"

    problemas = []
    algoritmos_detectados = set()

    for usuario, senha in registros:
        if not senha:
            problemas.append(f"usuário '{usuario}': senha vazia")
            continue

        algoritmo, seguro = _identificar_algoritmo(senha)
        algoritmos_detectados.add(algoritmo)

        if not seguro:
            problemas.append(f"usuário '{usuario}': {algoritmo}")

    if not problemas:
        algs = ", ".join(algoritmos_detectados)
        return f"Seguro — senhas armazenadas com hash adequado ({algs})"

    total = len(registros)
    vulneraveis = len(problemas)
    alg_detectado = list(algoritmos_detectados)[0] if len(algoritmos_detectados) == 1 else "múltiplos"

    # Define severidade com base no algoritmo detectado
    if "plaintext" in alg_detectado or "md5" in alg_detectado or "sha-1" in alg_detectado:
        nivel = "CRÍTICO"
    elif "formato desconhecido" in alg_detectado or "sha-256 (hex)" in alg_detectado:
        nivel = "ALTO"
    else:
        nivel = "MÉDIO"

    return (
        f"{nivel} - {vulneraveis}/{total} senha(s) com armazenamento inseguro. "
        f"Algoritmo detectado: {alg_detectado}. "
        f"Afetado(s): {', '.join(p.split(':')[0] for p in problemas[:3])}"
    )


if __name__ == "__main__":
    print(testar_hash_senha())
