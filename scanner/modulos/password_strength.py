"""
Módulo: Verificação de Força de Senha
Descrição: Verifica se usuários do banco possuem senhas fracas usando
           bcrypt, calcula entropia e reporta quantos usuários estão
           em risco.

Otimização: usa ThreadPoolExecutor para testar senhas em paralelo,
           reduzindo o tempo de ~28s para ~3-5s.
"""

import sys
import os
import math
import bcrypt
from concurrent.futures import ThreadPoolExecutor, as_completed

pasta_raiz = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, pasta_raiz)

from core.database import conectar

# Número de threads paralelas — bcrypt é CPU-bound, então 4-8 é o ideal
MAX_WORKERS = 6

# Top 60 senhas mais comuns (OWASP / SecLists adaptado)
SENHAS_FRACAS = [
    "123", "1234", "12345", "123456", "1234567", "12345678", "123456789",
    "0", "00", "000", "0000", "00000", "111", "1111", "11111", "111111",
    "admin", "admin123", "administrator", "root", "password", "passw0rd",
    "senha", "senha123", "abc123", "abcdef", "qwerty", "qwerty123",
    "letmein", "monkey", "dragon", "master", "iloveyou", "sunshine",
    "princess", "welcome", "shadow", "superman", "batman", "football",
    "baseball", "soccer", "hockey", "access", "login", "pass", "test",
    "guest", "user", "demo", "temp", "change", "changeme", "secret",
    "pass123", "1q2w3e", "1q2w3e4r", "zxcvbn", "asdfgh", "qazwsx",
    "trustno1", "696969", "mustang", "michael", "jessica", "letmein1",
]


# ─────────────────────────────────────────────────────────────
#  Cálculo de entropia
# ─────────────────────────────────────────────────────────────

def _calcular_entropia(senha: str) -> float:
    """
    Calcula a entropia da senha em bits.
    Fórmula: H = L * log2(N), onde L = comprimento e N = charset.
    """
    charset = 0
    if any(c.islower()  for c in senha): charset += 26
    if any(c.isupper()  for c in senha): charset += 26
    if any(c.isdigit()  for c in senha): charset += 10
    if any(not c.isalnum() for c in senha): charset += 32
    if charset == 0:
        return 0.0
    return round(len(senha) * math.log2(charset), 2)


def _classificar_entropia(bits: float) -> str:
    if bits < 28: return "muito fraca"
    if bits < 36: return "fraca"
    if bits < 60: return "razoável"
    if bits < 80: return "boa"
    return "muito boa"


# ─────────────────────────────────────────────────────────────
#  Teste de uma senha contra um hash (roda em thread)
# ─────────────────────────────────────────────────────────────

def _testar_senha(usuario: str, hash_armazenado: str, senha_fraca: str) -> tuple | None:
    """
    Testa uma senha fraca contra o hash do usuário via bcrypt.

    Retorna:
        (usuario, senha_fraca, entropia) se a senha bater, None caso contrário.
    """
    try:
        if bcrypt.checkpw(senha_fraca.encode(), hash_armazenado.encode()):
            return (usuario, senha_fraca, _calcular_entropia(senha_fraca))
    except Exception:
        # Hash malformado — trata como plaintext
        if hash_armazenado == senha_fraca:
            return (usuario, senha_fraca, _calcular_entropia(senha_fraca))
    return None


# ─────────────────────────────────────────────────────────────
#  Teste em paralelo para um usuário
# ─────────────────────────────────────────────────────────────

def _testar_usuario_paralelo(usuario: str, hash_armazenado: str) -> tuple | None:
    """
    Testa todas as senhas da wordlist contra o hash de um usuário
    usando threads paralelas. Para assim que encontrar a primeira.

    Retorna:
        (usuario, senha_fraca, entropia) ou None se não encontrar.
    """
    # Caso plaintext — detecta antes de tentar bcrypt
    if len(hash_armazenado) < 20 and not hash_armazenado.startswith("$"):
        return (usuario, hash_armazenado, _calcular_entropia(hash_armazenado))

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Submete todos os testes em paralelo
        futuros = {
            executor.submit(_testar_senha, usuario, hash_armazenado, senha): senha
            for senha in SENHAS_FRACAS
        }

        for futuro in as_completed(futuros):
            resultado = futuro.result()
            if resultado is not None:
                # Encontrou — cancela os demais e retorna imediatamente
                for f in futuros:
                    f.cancel()
                return resultado

    return None


# ─────────────────────────────────────────────────────────────
#  Função principal
# ─────────────────────────────────────────────────────────────

def testar_senha_fraca() -> str:
    """
    Verifica se usuários do banco possuem senhas fracas.

    Usa ThreadPoolExecutor para testar senhas em paralelo,
    reduzindo o tempo de execução de ~28s para ~3-5s.

    Retorna:
        str com prefixo de severidade, quantidade de usuários afetados
        e nível de entropia das senhas encontradas.
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

    total      = len(registros)
    vulneraveis = []   # [(usuario, senha_fraca, entropia)]
    plaintext   = []   # [(usuario, senha, entropia)]

    # Testa cada usuário em laço — cada usuário usa threads internamente
    for usuario, hash_armazenado in registros:
        if not hash_armazenado:
            continue

        resultado = _testar_usuario_paralelo(usuario, hash_armazenado)

        if resultado is None:
            continue

        _, senha_encontrada, entropia = resultado

        # Separa plaintext de hash fraco
        if len(hash_armazenado) < 20 and not hash_armazenado.startswith("$"):
            plaintext.append(resultado)
        else:
            vulneraveis.append(resultado)

    # ── Monta retorno ────────────────────────────────────────
    if plaintext:
        nomes = ", ".join(f"'{u}'" for u, _, _ in plaintext[:3])
        return (
            f"CRÍTICO - {len(plaintext)}/{total} usuário(s) com senha em plaintext. "
            f"Afetado(s): {nomes}"
        )

    if not vulneraveis:
        return f"Seguro — nenhuma senha fraca detectada entre {total} usuário(s)"

    entropia_media = round(
        sum(e for _, _, e in vulneraveis) / len(vulneraveis), 1
    )
    classif = _classificar_entropia(entropia_media)
    nomes   = ", ".join(f"'{u}'" for u, _, _ in vulneraveis[:3])
    sufixo  = f" (+{len(vulneraveis) - 3} outros)" if len(vulneraveis) > 3 else ""
    nivel   = "ALTO" if len(vulneraveis) / total >= 0.5 else "MÉDIO"

    return (
        f"{nivel} - {len(vulneraveis)}/{total} usuário(s) com senha fraca "
        f"(entropia média: {entropia_media} bits — {classif}). "
        f"Afetado(s): {nomes}{sufixo}"
    )


if __name__ == "__main__":
    import time
    inicio = time.perf_counter()
    print(testar_senha_fraca())
    print(f"\nTempo: {round(time.perf_counter() - inicio, 2)}s")
