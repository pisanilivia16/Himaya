"""
Arquivo: config.py
Descrição: Configurações centralizadas do scanner de segurança.
"""
import os

# ─── Caminhos ────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DIR_MODULOS = os.path.join(BASE_DIR, "scanner", "modulos")

# ─── Alvos dos testes ──────────────────────────────────────────
# O scanner testa TODOS os alvos listados aqui em cada módulo que
# depende de rede (sql_injection, brute_force, input_validation).
# Cada URL pode ser sobrescrita por variável de ambiente — útil no
# Render, caso o nome do serviço mude ou ganhe um sufixo.
ALVOS = [
    {
        "nome": "App Vulnerável",
        "url": os.getenv(
            "ALVO_URL_VULNERAVEL",
            "https://tcc-app-vulneravel.onrender.com/login",
        ),
    },
    {
        "nome": "App Segura",
        "url": os.getenv(
            "ALVO_URL_SEGURA",
            "https://tcc-app-segura.onrender.com/login",
        ),
    },
]

# Mantido por compatibilidade: usado como padrão quando um módulo é
# chamado isoladamente (ex.: python scanner/modulos/brute_force.py),
# sem passar por main.py — nesse caso, testa só o primeiro alvo.
URL_ALVO = ALVOS[0]["url"]
