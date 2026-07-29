"""
Arquivo: config.py
Descrição: Configurações centralizadas do scanner de segurança.
"""
import os

# ─── Caminhos ────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DIR_MODULOS = os.path.join(BASE_DIR, "scanner", "modulos")

# ─── Alvo padrão dos testes ───────────────────────────────────
# Pode ser sobrescrito por variável de ambiente, ex: no Render
# defina ALVO_URL apontando para o app vulnerável ou seguro.
URL_ALVO = os.getenv(
    "ALVO_URL",
    "https://testes-de-algoritimo-do-tcc.onrender.com/login"
)
