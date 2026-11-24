"""Monta os campos do formulário de login para as duas versões da aplicação.

A vulnerável recebe "usuario" e a segura recebe "email"; mandamos os dois,
cada app usa o que conhece e ignora o outro.
"""


def campos_login(usuario: str, senha: str) -> dict:
    email = usuario if "@" in usuario else f"{usuario}@seguro.local"
    return {"usuario": usuario, "email": email, "senha": senha}
