import os
import sqlite3
from contextlib import closing

import bcrypt

DB_PATH = os.environ.get(
    "DB_PATH", os.path.join(os.path.dirname(__file__), "..", "teste_seguro.db")
)

USUARIOS_INICIAIS = [
    ("admin", "admin@seguro.local", "S3nh@F0rte#99"),
    ("user1", "user1@seguro.local", "P@ssw0rd!2024"),
    ("user2", "user2@seguro.local", "Tr0ub4dor&3"),
]


def conectar() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def gerar_hash(senha: str) -> str:
    return bcrypt.hashpw(senha.encode(), bcrypt.gensalt(rounds=12)).decode()


def verificar_hash(senha: str, hash_armazenado: str) -> bool:
    try:
        return bcrypt.checkpw(senha.encode(), hash_armazenado.encode())
    except ValueError:
        return False


# Hash fixo usado quando o e-mail não existe, para que o tempo de resposta
# seja o mesmo nos dois casos (evita enumeração de usuários por timing).
HASH_FALSO = gerar_hash("senha-descartavel-sem-uso")


def inicializar_banco() -> None:
    with closing(conectar()) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario   TEXT UNIQUE NOT NULL,
                email     TEXT UNIQUE NOT NULL,
                senha     TEXT NOT NULL,
                criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        for usuario, email, senha in USUARIOS_INICIAIS:
            con.execute(
                "INSERT OR IGNORE INTO usuarios (usuario, email, senha) VALUES (?, ?, ?)",
                (usuario, email, gerar_hash(senha)),
            )
        con.commit()


def buscar_por_email(email: str) -> sqlite3.Row | None:
    with closing(conectar()) as con:
        return con.execute(
            "SELECT id, usuario, senha FROM usuarios WHERE email = ?", (email,)
        ).fetchone()


def criar_usuario(usuario: str, email: str, senha: str) -> bool:
    """Retorna False se usuário ou e-mail já existem (garantido pelo UNIQUE do banco)."""
    try:
        with closing(conectar()) as con:
            con.execute(
                "INSERT INTO usuarios (usuario, email, senha) VALUES (?, ?, ?)",
                (usuario, email, gerar_hash(senha)),
            )
            con.commit()
        return True
    except sqlite3.IntegrityError:
        return False
