"""
Módulo: core/database.py
Descrição: Gerencia a conexão com o banco de dados SQLite e
           a criação/população inicial das tabelas para os testes.
"""

import sqlite3
import os
import logging
import bcrypt

logger = logging.getLogger("scanner")

# Caminho absoluto do banco — sempre relativo a este arquivo,
# independente de onde o script for executado.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "..", "teste.db")

# Usuários de teste: (usuario, senha_plaintext, tipo)
# Mistura proposital de senhas fracas e fortes para o scanner detectar
USUARIOS_TESTE = [
    ("admin",  "123456",          "fraca"),     # detectável por password_strength
    ("user1",  "abc123",          "fraca"),     # detectável por password_strength
    ("user2",  "S3nh@F0rte#99",   "forte"),     # deve passar em todos os testes
    ("root",   "root",            "fraca"),     # detectável por brute_force também
]


def conectar() -> sqlite3.Connection:
    """
    Retorna uma conexão com o banco de dados SQLite.

    Raises:
        RuntimeError: se não for possível conectar ao banco.
    """
    try:
        con = sqlite3.connect(DB_PATH)
        con.row_factory = sqlite3.Row  # permite acessar colunas por nome
        return con
    except sqlite3.Error as e:
        logger.error(f"Falha ao conectar ao banco de dados: {e}")
        raise RuntimeError(f"Não foi possível conectar ao banco: {e}") from e


def criar_tabelas(cursor: sqlite3.Cursor) -> None:
    """Cria as tabelas necessárias caso não existam."""
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario  TEXT    UNIQUE NOT NULL,
            senha    TEXT    NOT NULL,
            tipo     TEXT    DEFAULT 'normal',
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)


def popular_usuarios(cursor: sqlite3.Cursor) -> None:
    """
    Insere os usuários de teste com senhas hashadas via bcrypt.
    Usa INSERT OR IGNORE para não duplicar em re-execuções.
    """
    for usuario, senha_plain, tipo in USUARIOS_TESTE:
        hash_senha = bcrypt.hashpw(senha_plain.encode(), bcrypt.gensalt()).decode()
        cursor.execute(
            "INSERT OR IGNORE INTO usuarios (usuario, senha, tipo) VALUES (?, ?, ?)",
            (usuario, hash_senha, tipo)
        )
        logger.debug(f"Usuário '{usuario}' inserido (tipo: {tipo})")


def inicializar_banco() -> None:
    """
    Inicializa o banco de dados: cria tabelas e popula com usuários de teste.
    Deve ser chamado uma vez antes de rodar os testes.
    """
    con = None
    try:
        con = conectar()
        cursor = con.cursor()
        criar_tabelas(cursor)
        popular_usuarios(cursor)
        con.commit()
        logger.info(f"Banco de dados inicializado em: {DB_PATH}")
    except Exception as e:
        logger.error(f"Erro ao inicializar banco: {e}")
        if con:
            con.rollback()
        raise
    finally:
        if con:
            con.close()


def resetar_banco() -> None:
    """
    Remove e recria o banco do zero.
    Útil para garantir estado limpo entre execuções de testes.
    """
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        logger.info("Banco de dados removido para reset.")
    inicializar_banco()


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")

    if "--reset" in sys.argv:
        resetar_banco()
        print("Banco resetado e recriado com sucesso.")
    else:
        inicializar_banco()
        print("Banco inicializado com sucesso.")