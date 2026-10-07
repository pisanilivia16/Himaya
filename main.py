"""
TCC - Scanner de Segurança
Autor: [Seu Nome]
Descrição: Scanner automatizado de vulnerabilidades para análise de segurança
"""

import os
import sys
import time
import logging
import argparse
import json
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import ALVOS
from scanner.modulos.sql_injection import testar_sql_injection
from scanner.modulos.brute_force import testar_bruteforce
from scanner.modulos.password_strength import testar_senha_fraca
from scanner.modulos.password_hash_check import testar_hash_senha
from scanner.modulos.input_validation import testar_validacao_entrada


# ─────────────────────────────────────────────
#  Configuração de logs
# ─────────────────────────────────────────────

def configurar_logger(verbose: bool = False) -> logging.Logger:
    """Configura o logger com saída no terminal e em arquivo."""
    os.makedirs("logs", exist_ok=True)
    nivel = logging.DEBUG if verbose else logging.INFO

    logger = logging.getLogger("scanner")
    logger.setLevel(nivel)

    fmt = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Handler: terminal
    ch = logging.StreamHandler()
    ch.setLevel(nivel)
    ch.setFormatter(fmt)

    # Handler: arquivo
    log_file = f"logs/scan_{datetime.now().strftime('%Y-%m-%d')}.log"
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    logger.addHandler(ch)
    logger.addHandler(fh)
    return logger


# ─────────────────────────────────────────────
#  Severidade
# ─────────────────────────────────────────────

NIVEIS_SEVERIDADE = {
    "CRÍTICO": 4,
    "ALTO":    3,
    "MÉDIO":   2,
    "BAIXO":   1,
    "SEGURO":  0,
    "ERRO":   -1,
}

CORES_TERMINAL = {
    "CRÍTICO": "\033[91m",   # Vermelho
    "ALTO":    "\033[33m",   # Amarelo
    "MÉDIO":   "\033[93m",   # Amarelo claro
    "BAIXO":   "\033[94m",   # Azul claro
    "SEGURO":  "\033[92m",   # Verde
    "ERRO":    "\033[90m",   # Cinza
    "RESET":   "\033[0m",
}

def extrair_severidade(resultado: str) -> str:
    """Extrai o nível de severidade a partir da string retornada pelo módulo."""
    resultado_upper = resultado.upper()
    for nivel in NIVEIS_SEVERIDADE:
        if resultado_upper.startswith(nivel):
            return nivel
    # Se começa com "Seguro" ou não tem prefixo conhecido
    if resultado_upper.startswith("SEGURO") or "SEGURO" in resultado_upper:
        return "SEGURO"
    return "SEGURO"

def colorir(texto: str, nivel: str) -> str:
    """Aplica cor ANSI ao texto conforme o nível de severidade."""
    cor = CORES_TERMINAL.get(nivel, "")
    reset = CORES_TERMINAL["RESET"]
    return f"{cor}{texto}{reset}"


# ─────────────────────────────────────────────
#  Execução dos módulos
# ─────────────────────────────────────────────

MODULOS_DISPONIVEIS = {
    "sql_injection":    ("SQL Injection",       testar_sql_injection),
    "brute_force":      ("Força Bruta",          testar_bruteforce),
    "password_strength":("Senha Fraca",          testar_senha_fraca),
    "password_hash":    ("Hash de Senha",        testar_hash_senha),
    "input_validation": ("Validação de Entrada", testar_validacao_entrada),
}

# Módulos que atacam uma aplicação via HTTP e, portanto, rodam uma vez
# POR ALVO (config.ALVOS) — os outros (password_strength, password_hash)
# testam direto o banco de dados e rodam uma única vez.
MODULOS_POR_ALVO = {"sql_injection", "brute_force", "input_validation"}


def executar_modulo(nome_chave: str, logger: logging.Logger,
                     url: str = None, nome_alvo: str = None,
                     kwargs_extra: dict = None) -> dict:
    """
    Executa um módulo de teste e retorna um dicionário com:
    nome, resultado, severidade, tempo de execução e status.

    Se `url` for informado, o módulo é executado contra esse alvo
    específico e `nome_alvo` é anexado ao nome de exibição e gravado
    no campo "alvo" do resultado, para que os relatórios possam ser
    separados por app depois. `kwargs_extra` repassa argumentos extras
    para a função do módulo (ex.: incluir_banco=False no sql_injection).
    """
    nome_exibicao, funcao = MODULOS_DISPONIVEIS[nome_chave]
    if nome_alvo:
        nome_exibicao = f"{nome_exibicao} ({nome_alvo})"
    logger.debug(f"Iniciando módulo: {nome_exibicao}")

    inicio = time.perf_counter()
    try:
        extras = kwargs_extra or {}
        resultado = funcao(url, **extras) if url is not None else funcao(**extras)
        status = "ok"
    except Exception as e:
        resultado = f"ERRO - Falha inesperada: {e}"
        status = "falha"
        logger.error(f"Erro no módulo '{nome_exibicao}': {e}")
    fim = time.perf_counter()

    duracao = round(fim - inicio, 4)
    severidade = extrair_severidade(resultado)

    logger.info(f"[{severidade}] {nome_exibicao}: {resultado} ({duracao}s)")

    return {
        "modulo":     nome_chave,
        "nome":       nome_exibicao,
        "resultado":  resultado,
        "severidade": severidade,
        "duracao_s":  duracao,
        "status":     status,
        "alvo":       nome_alvo,   # None = módulo geral, não específico de um app
    }


def calcular_score(resultados: list[dict]) -> dict:
    """
    Calcula o score geral de segurança do sistema.
    Score = % de módulos sem vulnerabilidades críticas/altas.
    """
    total = len(resultados)
    seguros = sum(
        1 for r in resultados
        if r["severidade"] in ("SEGURO", "BAIXO")
    )
    criticos = sum(1 for r in resultados if r["severidade"] == "CRÍTICO")
    altos    = sum(1 for r in resultados if r["severidade"] == "ALTO")
    medios   = sum(1 for r in resultados if r["severidade"] == "MÉDIO")
    erros    = sum(1 for r in resultados if r["severidade"] == "ERRO")

    score = round((seguros / total) * 100) if total > 0 else 0

    if score == 100:
        classificacao = "EXCELENTE"
    elif score >= 80:
        classificacao = "BOM"
    elif score >= 60:
        classificacao = "REGULAR"
    elif score >= 40:
        classificacao = "RUIM"
    else:
        classificacao = "CRÍTICO"

    return {
        "score":         score,
        "classificacao": classificacao,
        "total":         total,
        "seguros":       seguros,
        "criticos":      criticos,
        "altos":         altos,
        "medios":        medios,
        "erros":         erros,
    }


# ─────────────────────────────────────────────
#  Geração de relatórios
# ─────────────────────────────────────────────

def gerar_relatorio_txt(resultados: list[dict], score: dict, caminho: str,
                         titulo: str = None):
    """Gera relatório em texto simples. `titulo` identifica o alvo (app) deste relatório."""
    with open(caminho, "w", encoding="utf-8") as f:
        f.write("=" * 50 + "\n")
        f.write("     RELATÓRIO DE SEGURANÇA - TCC\n")
        f.write("=" * 50 + "\n\n")
        if titulo:
            f.write(f"Alvo            : {titulo}\n")
        f.write(f"Data da análise : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
        f.write(f"Score geral     : {score['score']}% — {score['classificacao']}\n")
        f.write(f"Módulos testados: {score['total']}\n\n")
        f.write("-" * 50 + "\n")
        f.write("RESULTADOS POR MÓDULO\n")
        f.write("-" * 50 + "\n")
        for r in resultados:
            f.write(f"\n[{r['severidade']}] {r['nome']}\n")
            f.write(f"  Resultado : {r['resultado']}\n")
            f.write(f"  Duração   : {r['duracao_s']}s\n")
        f.write("\n" + "=" * 50 + "\n")
        f.write(f"Críticos: {score['criticos']} | Altos: {score['altos']} | "
                f"Médios: {score['medios']} | Seguros: {score['seguros']}\n")


def gerar_relatorio_json(resultados: list[dict], score: dict, caminho: str,
                          titulo: str = None):
    """Gera relatório em JSON estruturado. `titulo` identifica o alvo (app) deste relatório."""
    payload = {
        "metadata": {
            "data_analise": datetime.now().isoformat(),
            "versao_scanner": "1.0.0",
            "alvo": titulo,
        },
        "score": score,
        "resultados": resultados,
    }
    with open(caminho, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def gerar_relatorio_html(resultados: list[dict], score: dict, caminho: str,
                          titulo: str = None):
    """Gera relatório visual em HTML com tabela colorida por severidade. `titulo` identifica o alvo (app) deste relatório."""

    COR_SEVERIDADE = {
        "CRÍTICO": ("#fde8e8", "#c53030", "#fff5f5"),
        "ALTO":    ("#fef3c7", "#b45309", "#fffbeb"),
        "MÉDIO":   ("#fef9c3", "#854d0e", "#fefce8"),
        "BAIXO":   ("#dbeafe", "#1e40af", "#eff6ff"),
        "SEGURO":  ("#dcfce7", "#166534", "#f0fdf4"),
        "ERRO":    ("#f3f4f6", "#374151", "#f9fafb"),
    }

    score_cor = {
        "EXCELENTE": "#166534",
        "BOM":       "#1e40af",
        "REGULAR":   "#854d0e",
        "RUIM":      "#b45309",
        "CRÍTICO":   "#c53030",
    }.get(score["classificacao"], "#374151")

    linhas_tabela = ""
    for r in resultados:
        bg, text_color, row_bg = COR_SEVERIDADE.get(r["severidade"], ("#f9fafb", "#111", "#fff"))
        badge = f'<span style="background:{bg};color:{text_color};padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600">{r["severidade"]}</span>'
        linhas_tabela += f"""
        <tr style="background:{row_bg}">
            <td style="padding:12px 16px;font-weight:500">{r['nome']}</td>
            <td style="padding:12px 16px">{badge}</td>
            <td style="padding:12px 16px;color:#555;font-size:13px">{r['resultado']}</td>
            <td style="padding:12px 16px;color:#888;font-size:13px;text-align:right">{r['duracao_s']}s</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <title>Relatório de Segurança</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: system-ui, -apple-system, sans-serif; background: #f8fafc; color: #1a202c; padding: 40px 24px; }}
    .container {{ max-width: 860px; margin: 0 auto; }}
    h1 {{ font-size: 22px; font-weight: 700; margin-bottom: 4px; }}
    .subtitle {{ color: #64748b; font-size: 13px; margin-bottom: 32px; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 16px; margin-bottom: 32px; }}
    .card {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 16px; text-align: center; }}
    .card .valor {{ font-size: 28px; font-weight: 700; }}
    .card .label {{ font-size: 12px; color: #64748b; margin-top: 4px; }}
    .score-card {{ border-color: {score_cor}; }}
    .score-card .valor {{ color: {score_cor}; }}
    table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 12px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
    thead tr {{ background: #1e293b; color: #fff; }}
    thead th {{ padding: 12px 16px; text-align: left; font-size: 13px; font-weight: 600; }}
    tbody tr:not(:last-child) {{ border-bottom: 1px solid #f1f5f9; }}
    .footer {{ margin-top: 24px; text-align: center; font-size: 12px; color: #94a3b8; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>Relatório de Segurança</h1>
    <p class="subtitle">Gerado em {datetime.now().strftime('%d/%m/%Y às %H:%M:%S')}</p>

    <div class="cards">
      <div class="card score-card">
        <div class="valor">{score['score']}%</div>
        <div class="label">Score geral</div>
      </div>
      <div class="card">
        <div class="valor" style="color:#c53030">{score['criticos']}</div>
        <div class="label">Críticos</div>
      </div>
      <div class="card">
        <div class="valor" style="color:#b45309">{score['altos']}</div>
        <div class="label">Altos</div>
      </div>
      <div class="card">
        <div class="valor" style="color:#854d0e">{score['medios']}</div>
        <div class="label">Médios</div>
      </div>
      <div class="card">
        <div class="valor" style="color:#166534">{score['seguros']}</div>
        <div class="label">Seguros</div>
      </div>
    </div>

    <table>
      <thead>
        <tr>
          <th>Módulo</th>
          <th>Severidade</th>
          <th>Resultado</th>
          <th style="text-align:right">Duração</th>
        </tr>
      </thead>
      <tbody>
        {linhas_tabela}
      </tbody>
    </table>

    <p class="footer">TCC — Scanner de Segurança · Score: {score['score']}% ({score['classificacao']})</p>
  </div>
</body>
</html>"""

    with open(caminho, "w", encoding="utf-8") as f:
        f.write(html)


# ─────────────────────────────────────────────
#  Interface de linha de comando
# ─────────────────────────────────────────────

def construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="TCC - Scanner de Segurança: testa vulnerabilidades em aplicações web locais.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--modulo",
        choices=list(MODULOS_DISPONIVEIS.keys()) + ["todos"],
        default="todos",
        help=(
            "Módulo específico a executar. Opções:\n"
            "  sql_injection     — Testa SQL Injection\n"
            "  brute_force       — Testa força bruta\n"
            "  password_strength — Testa senhas fracas\n"
            "  password_hash     — Verifica hash de senhas\n"
            "  input_validation  — Valida entradas\n"
            "  todos             — Executa todos (padrão)"
        ),
    )
    parser.add_argument(
        "--saida",
        choices=["txt", "html", "json", "todos"],
        default="todos",
        help="Formato do relatório gerado (padrão: todos)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Exibe logs detalhados de debug no terminal",
    )
    return parser


# ─────────────────────────────────────────────
#  Exibição no terminal
# ─────────────────────────────────────────────

def exibir_banner():
    print("\n" + "=" * 52)
    print("        SCANNER DE SEGURANÇA — TCC")
    print("=" * 52)

def exibir_resultados(resultados: list[dict], score: dict):
    print("\n RESULTADOS POR MÓDULO\n")
    for r in resultados:
        linha = f"  [{r['severidade']:8}]  {r['nome']:25} {r['duracao_s']}s"
        print(colorir(linha, r["severidade"]))

    print("\n" + "-" * 52)
    print(f"  Score geral : {colorir(str(score['score']) + '%', 'SEGURO' if score['score'] >= 80 else 'ALTO')} — {score['classificacao']}")
    print(f"  Críticos: {score['criticos']}  Altos: {score['altos']}  Médios: {score['medios']}  Seguros: {score['seguros']}")
    print("-" * 52 + "\n")


# ─────────────────────────────────────────────
#  Ponto de entrada
# ─────────────────────────────────────────────

def main():
    parser = construir_parser()
    args = parser.parse_args()

    logger = configurar_logger(verbose=args.verbose)
    exibir_banner()

    # Seleciona quais módulos executar
    if args.modulo == "todos":
        modulos_para_rodar = list(MODULOS_DISPONIVEIS.keys())
    else:
        modulos_para_rodar = [args.modulo]

    logger.info(f"Iniciando scan. Módulos: {modulos_para_rodar}")
    inicio_total = time.perf_counter()

    modulos_por_alvo_selecionados = [c for c in modulos_para_rodar if c in MODULOS_POR_ALVO]
    modulos_gerais_selecionados   = [c for c in modulos_para_rodar if c not in MODULOS_POR_ALVO]

    # Executa como SCANS SEPARADOS, em sequência: primeiro um scan completo
    # na aplicação vulnerável, depois um scan completo na aplicação segura —
    # em vez de intercalar módulo a módulo. Os módulos gerais (que não
    # dependem de URL, ex. password_strength/password_hash) rodam dentro
    # do primeiro scan, já que não pertencem a nenhum alvo específico.
    resultados = []
    if ALVOS:
        for indice, alvo in enumerate(ALVOS):
            print(f"\n▶ Scan {indice + 1}/{len(ALVOS)}: {alvo['nome']} ({alvo['url']})")
            logger.info(f"Iniciando scan {indice + 1}/{len(ALVOS)}: {alvo['nome']}")

            for chave in modulos_por_alvo_selecionados:
                if chave == "sql_injection":
                    # O vetor "banco" do sql_injection não depende do alvo
                    # (testa sempre o mesmo banco compartilhado) — só faz
                    # sentido rodar uma vez, no primeiro scan.
                    resultado = executar_modulo(
                        chave, logger, url=alvo["url"], nome_alvo=alvo["nome"],
                        kwargs_extra={"incluir_banco": indice == 0},
                    )
                else:
                    resultado = executar_modulo(
                        chave, logger, url=alvo["url"], nome_alvo=alvo["nome"]
                    )
                resultados.append(resultado)

            # Módulos gerais (não específicos de alvo) rodam só uma vez,
            # junto do primeiro scan.
            if indice == 0:
                for chave in modulos_gerais_selecionados:
                    resultado = executar_modulo(chave, logger)
                    resultados.append(resultado)
    else:
        # Sem alvos configurados (config.ALVOS vazio) — roda só os módulos gerais.
        for chave in modulos_gerais_selecionados:
            resultado = executar_modulo(chave, logger)
            resultados.append(resultado)

    fim_total = time.perf_counter()
    duracao_total = round(fim_total - inicio_total, 2)
    logger.info(f"Scan concluído em {duracao_total}s")

    # Calcula score e exibe no terminal
    score = calcular_score(resultados)
    exibir_resultados(resultados, score)

    # Gera relatórios — um conjunto de arquivos POR ALVO testado, para
    # não misturar os resultados de app vulnerável e app segura no
    # mesmo arquivo.
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")

    formatos = (
        ["txt", "html", "json"] if args.saida == "todos" else [args.saida]
    )

    def slugificar(nome: str) -> str:
        troca = str.maketrans("áàâãéêíóôõúüç", "aaaaeeiooouuc")
        return nome.lower().translate(troca).replace(" ", "_")

    # Nomes dos alvos presentes nos resultados desta execução (na ordem
    # de config.ALVOS). Resultados sem módulos por-alvo (ex.: rodando só
    # --modulo password_strength) ainda geram um único relatório "geral".
    nomes_alvos = [a["nome"] for a in ALVOS if any(
        r["alvo"] == a["nome"] for r in resultados
    )]
    grupos = nomes_alvos or [None]   # None = relatório único "geral"

    caminhos_gerados = []  # [(formato, titulo_ou_None, caminho)]

    for nome_alvo in grupos:
        # Resultados deste alvo: os específicos dele + os gerais (alvo=None,
        # ex. password_strength/password_hash), que valem para qualquer app.
        resultados_grupo = [
            r for r in resultados if r["alvo"] in (nome_alvo, None)
        ]
        score_grupo = calcular_score(resultados_grupo)

        sufixo = f"_{slugificar(nome_alvo)}" if nome_alvo else ""
        prefixo = f"reports/relatorio{sufixo}_{timestamp}"

        if "txt" in formatos:
            caminho = f"{prefixo}.txt"
            gerar_relatorio_txt(resultados_grupo, score_grupo, caminho, titulo=nome_alvo)
            caminhos_gerados.append(("txt", nome_alvo, caminho))

        if "json" in formatos:
            caminho = f"{prefixo}.json"
            gerar_relatorio_json(resultados_grupo, score_grupo, caminho, titulo=nome_alvo)
            caminhos_gerados.append(("json", nome_alvo, caminho))

        if "html" in formatos:
            caminho = f"{prefixo}.html"
            gerar_relatorio_html(resultados_grupo, score_grupo, caminho, titulo=nome_alvo)
            caminhos_gerados.append(("html", nome_alvo, caminho))

    print("  Relatórios gerados:")
    for fmt, nome_alvo, path in caminhos_gerados:
        rotulo = nome_alvo or "Geral"
        print(f"    [{fmt.upper()}] {rotulo}: {path}")
    print()


if __name__ == "__main__":
    main()
