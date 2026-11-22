import re

from email_validator import EmailNotValidError, validate_email

SENHA_MIN = 8
SENHA_MAX_BYTES = 72  # limite do bcrypt; acima disso a senha seria truncada em silêncio
EMAIL_MAX = 254
USUARIO_MAX = 64

SENHAS_COMUNS = {
    "password", "senha", "senha123", "admin", "admin123", "qwerty", "qwerty123",
    "letmein", "welcome", "iloveyou", "abc123", "passw0rd", "p@ssw0rd",
    "minhasenha", "mudar123", "teste123", "brasil", "123456", "12345678",
}
_LEET = str.maketrans("@4310$5!", "aaeioss1")
_TECLADO = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "abcdefghijklmnopqrstuvwxyz", "0123456789")


def normalizar_email(email: str) -> str:
    return email.strip().lower()[:EMAIL_MAX]


def validar_email(email: str) -> tuple[str | None, str]:
    """Retorna (email_normalizado, erro). Não consulta DNS."""
    try:
        resultado = validate_email(email.strip(), check_deliverability=False)
    except EmailNotValidError:
        return None, "Informe um e-mail válido."
    normalizado = resultado.normalized.lower()
    if len(normalizado) > EMAIL_MAX:
        return None, "Informe um e-mail válido."
    return normalizado, ""


def _tem_sequencia(texto: str, tamanho: int = 4) -> bool:
    texto = texto.lower()
    for base in _TECLADO:
        for ordem in (base, base[::-1]):
            for i in range(len(ordem) - tamanho + 1):
                if ordem[i:i + tamanho] in texto:
                    return True
    return False


def validar_senha(senha: str, email: str = "", usuario: str = "") -> str:
    """Retorna a mensagem de erro, ou string vazia se a senha atende à política."""
    if len(senha) < SENHA_MIN:
        return f"A senha deve ter no mínimo {SENHA_MIN} caracteres."
    if len(senha.encode()) > SENHA_MAX_BYTES:
        return f"A senha deve ter no máximo {SENHA_MAX_BYTES} bytes."
    if not re.search(r"[A-Z]", senha):
        return "A senha deve conter ao menos uma letra maiúscula."
    if not re.search(r"[a-z]", senha):
        return "A senha deve conter ao menos uma letra minúscula."
    if not re.search(r"\d", senha):
        return "A senha deve conter ao menos um número."
    if not re.search(r"[^\w\s]|_", senha):
        return "A senha deve conter ao menos um caractere especial."

    simples = senha.lower().translate(_LEET)
    if (
        senha.lower() in SENHAS_COMUNS
        or simples in SENHAS_COMUNS
        or re.search(r"(.)\1{2,}", senha)
        or _tem_sequencia(senha)
    ):
        return "Senha muito previsível. Evite palavras comuns, sequências e repetições."

    for referencia in (email.split("@")[0], usuario):
        if len(referencia) >= 3 and referencia.lower() in senha.lower():
            return "A senha não pode conter seu e-mail ou nome de usuário."
    return ""
