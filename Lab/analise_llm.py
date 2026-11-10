"""
Submete os arquivos pré-processados (Lab/dataset_llm) aos LLMs via Ollama local,
usando o prompt estruturado definido no artigo original.

Pré-requisitos (rodar no Windows, fora desta VM):
    1. Instalar o Ollama: https://ollama.com/download
    2. Baixar os modelos usados no artigo:
         ollama pull codellama
         ollama pull deepseek-coder
    3. Deixar o serviço do Ollama rodando (ele inicia automaticamente após a
       instalação; a API fica disponível em http://localhost:11434)

Uso:
    python analise_llm.py                     # roda os dois modelos em todo o dataset_llm
    python analise_llm.py --model codellama    # roda só um modelo
    python analise_llm.py --limit 3            # só os primeiros 3 arquivos (teste rápido)

Saída:
    resultados/llm/<modelo>/<arquivo>.json   -> resposta individual (bruta + parseada)
    resultados/llm/resumo_<modelo>.json      -> agregado de todas as respostas do modelo
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# Caminhos relativos ao local deste script (Lab/), não ao diretório de execução,
# para evitar o mesmo bug de caminho do diretiva_preprocessamento.py
SCRIPT_DIR = Path(__file__).resolve().parent
DIR_LLM = SCRIPT_DIR / "dataset_llm"
OUT_DIR = SCRIPT_DIR.parent / "resultados" / "llm"

OLLAMA_URL = "http://localhost:11434/api/generate"
MODELOS_PADRAO = ["codellama", "deepseek-coder"]

PROMPT_TEMPLATE = '''Analise os riscos de segurança no código abaixo, seguindo o OWASP Top 10. Retorne APENAS se houver vulnerabilidades, no formato JSON abaixo. Caso contrário, retorne "Código seguro".
{{
"Arquivo": "Nome do arquivo",
"Trecho Vulnerável": "O snippet de código específico que contém a vulnerabilidade",
"Tipo da Vulnerabilidade": "A categoria da vulnerabilidade",
"Descrição Breve": "Uma explicação concisa (1-2 frases) de por que esse trecho é vulnerável"
}}

Arquivo: {filename}
Código:
{code}
'''


def listar_arquivos(diretorio: Path):
    """Busca recursiva por .ts/.js dentro de SAFE/ e VULN/, mantendo o rótulo real."""
    arquivos = []
    for rotulo in ("SAFE", "VULN"):
        base = diretorio / rotulo
        if not base.exists():
            continue
        for root, _, files in os.walk(base):
            for f in sorted(files):
                if f.lower().endswith((".ts", ".js")):
                    caminho = Path(root) / f
                    arquivos.append((rotulo, caminho))
    return sorted(arquivos, key=lambda x: str(x[1]))


def extrair_json(texto: str):
    """Tenta extrair o primeiro objeto JSON válido da resposta do modelo."""
    texto = texto.strip()
    if texto.lower().startswith("código seguro") or texto.lower().startswith('"código seguro"'):
        return {"status": "seguro", "raw": texto}
    # tenta parse direto
    try:
        return json.loads(texto)
    except json.JSONDecodeError:
        pass
    # tenta achar o primeiro bloco { ... } via regex não-ávido
    match = re.search(r"\{.*\}", texto, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    return None


def chamar_ollama(modelo: str, prompt: str, timeout: int = 300) -> str:
    payload = json.dumps({
        "model": modelo,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.1},
    }).encode("utf-8")
    req = urllib.request.Request(
        OLLAMA_URL, data=payload, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    return body.get("response", "")


def checar_ollama_disponivel():
    try:
        urllib.request.urlopen("http://localhost:11434/api/tags", timeout=5)
        return True
    except (urllib.error.URLError, ConnectionError):
        return False


def executar(modelos, limite=None):
    if not checar_ollama_disponivel():
        print("[!] ERRO: não consegui falar com o Ollama em http://localhost:11434")
        print("    Verifique se o serviço está rodando (ele deve iniciar junto com o Windows")
        print("    após a instalação, ou rode 'ollama serve' manualmente).")
        sys.exit(1)

    arquivos = listar_arquivos(DIR_LLM)
    if not arquivos:
        print(f"[!] ERRO: nenhum arquivo .ts/.js encontrado em {DIR_LLM}")
        sys.exit(1)

    if limite:
        arquivos = arquivos[:limite]

    for modelo in modelos:
        out_modelo = OUT_DIR / modelo
        out_modelo.mkdir(parents=True, exist_ok=True)
        resumo = []

        print(f"\n[*] Modelo: {modelo} — {len(arquivos)} arquivo(s)")
        for idx, (rotulo, caminho) in enumerate(arquivos, 1):
            nome = caminho.name
            codigo = caminho.read_text(encoding="utf-8", errors="ignore")
            prompt = PROMPT_TEMPLATE.format(filename=nome, code=codigo)

            print(f"  [{idx:02d}/{len(arquivos)}] ({rotulo}) {nome} ...", end=" ", flush=True)
            inicio = time.time()
            try:
                resposta_bruta = chamar_ollama(modelo, prompt)
                status = "ok"
            except Exception as exc:  # timeout, conexão, etc.
                resposta_bruta = ""
                status = f"erro: {exc}"
            duracao = time.time() - inicio

            parseado = extrair_json(resposta_bruta) if resposta_bruta else None

            registro = {
                "arquivo": nome,
                "rotulo_real": rotulo,  # SAFE ou VULN, conforme o dataset
                "status_chamada": status,
                "duracao_segundos": round(duracao, 1),
                "resposta_bruta": resposta_bruta,
                "resposta_parseada": parseado,
            }
            resumo.append(registro)

            (out_modelo / f"{nome}.json").write_text(
                json.dumps(registro, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            print(f"{status} ({duracao:.1f}s)")

        OUT_DIR.mkdir(parents=True, exist_ok=True)
        (OUT_DIR / f"resumo_{modelo}.json").write_text(
            json.dumps(resumo, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"[✔] Resumo salvo em {OUT_DIR / f'resumo_{modelo}.json'}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--model", action="append", dest="modelos",
        help="Nome do modelo Ollama a rodar (pode repetir a flag). Padrão: codellama e deepseek-coder.",
    )
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Limita a quantidade de arquivos (útil para um teste rápido).",
    )
    args = parser.parse_args()
    executar(args.modelos or MODELOS_PADRAO, args.limit)
