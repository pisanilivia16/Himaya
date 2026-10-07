"""
Arquivo: server.py
Descrição: Wrapper web para o scanner, usado no deploy do Render.

O Render exige que todo "Web Service" fique escutando numa porta
continuamente. O main.py é um SCRIPT — ele roda o scan e termina — então,
sozinho, ele não funciona como Web Service no Render (o serviço cai /
reinicia em loop e nenhum link fica disponível).

Este arquivo resolve isso: sobe um servidor Flask simples que:
  - dispara um scan completo (main.py) em segundo plano ao iniciar
  - serve uma página com a lista de relatórios já gerados
  - permite disparar um novo scan a qualquer momento pela rota /rodar
  - serve cada relatório HTML pela rota /reports/<arquivo>
"""

from flask import Flask, send_from_directory, redirect, url_for
import os
import sys
import glob
import html
import threading
import subprocess
from datetime import datetime

app = Flask(__name__)

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

_status = {"rodando": False, "ultima_execucao": None, "ultimo_erro": None}


def _rodar_scan_bg() -> None:
    """Executa 'python main.py --saida html' como subprocesso, em background."""
    _status["rodando"] = True
    _status["ultimo_erro"] = None
    try:
        resultado = subprocess.run(
            [sys.executable, "main.py", "--saida", "html"],
            cwd=BASE_DIR, capture_output=True, text=True, timeout=600,
        )
        if resultado.returncode != 0:
            _status["ultimo_erro"] = resultado.stderr[-2000:] or "Scan terminou com erro (sem detalhes)."
    except Exception as e:
        _status["ultimo_erro"] = str(e)
    finally:
        _status["rodando"] = False
        _status["ultima_execucao"] = datetime.now().strftime("%d/%m/%Y %H:%M:%S")


def _listar_relatorios_html() -> list[str]:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    arquivos = glob.glob(os.path.join(REPORTS_DIR, "*.html"))
    arquivos.sort(key=os.path.getmtime, reverse=True)
    return [os.path.basename(a) for a in arquivos]


@app.route("/")
def home():
    relatorios = _listar_relatorios_html()
    itens = "".join(
        f'<li><a href="/reports/{html.escape(nome)}">{html.escape(nome)}</a></li>'
        for nome in relatorios
    ) or "<li>Nenhum relatório ainda.</li>"

    if _status["rodando"]:
        status_txt = "⏳ Rodando um scan agora... atualize a página em alguns segundos."
    elif _status["ultimo_erro"]:
        status_txt = f"⚠ Último scan terminou com erro: {html.escape(_status['ultimo_erro'][:300])}"
    elif _status["ultima_execucao"]:
        status_txt = f"✓ Última execução: {_status['ultima_execucao']}"
    else:
        status_txt = "Nenhum scan rodou ainda nesta instância."

    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <title>Scanner Himaya — TCC</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 640px; margin: 60px auto; line-height: 1.6; color: #1a202c; padding: 0 20px; }}
    a {{ color: #1a6cf5; }}
    .status {{ background: #f0f4ff; border: 1px solid #dce4f5; border-radius: 8px; padding: 12px 16px; margin: 16px 0; font-size: 14px; }}
    .botao {{ display: inline-block; margin: 12px 0; padding: 10px 18px; background: #1a6cf5; color: #fff; text-decoration: none; border-radius: 8px; font-weight: 600; }}
    ul {{ padding-left: 20px; }}
    li {{ margin-bottom: 6px; }}
  </style>
</head>
<body>
  <h1>Scanner de Segurança — TCC</h1>
  <div class="status">{status_txt}</div>
  <a class="botao" href="/rodar">▶ Rodar novo scan</a>
  <h2>Relatórios gerados</h2>
  <ul>{itens}</ul>
</body>
</html>"""


@app.route("/rodar")
def rodar():
    if not _status["rodando"]:
        threading.Thread(target=_rodar_scan_bg, daemon=True).start()
    return redirect(url_for("home"))


@app.route("/reports/<path:nome_arquivo>")
def ver_relatorio(nome_arquivo):
    return send_from_directory(REPORTS_DIR, nome_arquivo)


# Dispara um primeiro scan em segundo plano assim que o serviço sobe,
# para já existir relatório disponível sem precisar clicar em "Rodar".
threading.Thread(target=_rodar_scan_bg, daemon=True).start()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5002))
    app.run(host="0.0.0.0", port=port, debug=False)
