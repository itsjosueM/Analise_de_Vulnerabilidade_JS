import os, json, requests, time, sys

# ============================================================
# PROMPT EXTRAÍDO LITERALMENTE DO CÓDIGO 1 DO ARTIGO
# (Pimentel & Progetti, 2025, p. 6)
# ============================================================
PROMPT_ARTIGO = """Analise os riscos de segurança no código abaixo, seguindo o OWASP Top 10. Retorne APENAS se houver vulnerabilidades, no formato JSON abaixo. Caso contrário, retorne "Código seguro".

{{
  "Arquivo": "Nome do arquivo",
  "Trecho Vulnerável": "O snippet de código específico que contém a vulnerabilidade.",
  "Tipo da Vulnerabilidade": "A categoria da vulnerabilidade",
  "Descrição Breve": "Uma explicação concisa (1-2 frases) de por que esse trecho é vulnerável"
}}"""

def verificar_ollama():
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=5)
        r.raise_for_status()
        modelos = [m["name"] for m in r.json().get("models", [])]
        print(f"[OK] Ollama ativo. Modelos disponíveis: {modelos}")
        return True
    except Exception as e:
        print(f"[ERRO] Ollama não está acessível em localhost:11434 — {e}")
        print("       Inicie o Ollama e rode 'ollama pull deepseek-coder:1.3b' e 'ollama pull codellama:7b'")
        return False

def montar_prompt(codigo: str) -> str:
    """Prompt do artigo + código, sem intervenções adicionais."""
    return PROMPT_ARTIGO + "\n\n" + codigo

def analisar(modelo: str, codigo: str, timeout: int = 300) -> str:
    payload = {
        "model": modelo,
        "prompt": montar_prompt(codigo),
        "stream": False,
        # NÃO usar "format": "json" — o artigo não menciona esse parâmetro
    }
    try:
        r = requests.post("http://localhost:11434/api/generate", json=payload, timeout=timeout)
        r.raise_for_status()
        return r.json().get("response", "")
    except Exception as e:
        return json.dumps({"erro": str(e)})

def main():
    if not verificar_ollama():
        sys.exit(1)

    pastas_entrada = {
        "VULN": "dataset_llm/VULN",
        "SAFE": "dataset_llm/SAFE",
    }
    pasta_out = "resultados/llm"
    os.makedirs(pasta_out, exist_ok=True)

    # Carrega resultados anteriores (permite retomar)
    saida_json = os.path.join(pasta_out, "llm_results.json")
    if os.path.exists(saida_json):
        with open(saida_json, encoding="utf-8") as f:
            resultados = json.load(f)
        print(f"[INFO] Retomando de {saida_json} ({len(resultados.get('deepseek', {}))} arquivos já processados)")
    else:
        resultados = {"deepseek": {}, "codellama": {}}

    modelos = {"deepseek": "deepseek-coder:1.3b", "codellama": "codellama:7b"}

    total = sum(len([f for f in files if f.endswith((".ts", ".js"))])
                for _, _, files in os.walk("dataset_llm"))

    contador = 0
    for categoria, pasta in pastas_entrada.items():
        for root, _, files in os.walk(pasta):
            for f in sorted(files):
                if not f.endswith((".ts", ".js")):
                    continue
                caminho = os.path.join(root, f)
                rel = f"{categoria}/{f}"  # flat, sem subpastas
                with open(caminho, "r", encoding="utf-8") as fh:
                    codigo = fh.read()

                for apelido, modelo in modelos.items():
                    contador += 1
                    # Pula se já processado
                    if rel in resultados.get(apelido, {}) and resultados[apelido][rel].strip():
                        print(f"[{contador}/{total*2}] [SKIP] {apelido} :: {rel}")
                        continue
                    print(f"[{contador}/{total*2}] [{apelido}] {rel} ...", end="", flush=True)
                    resp = analisar(modelo, codigo)
                    resultados.setdefault(apelido, {})[rel] = resp
                    # Salva incrementalmente (proteção contra queda)
                    with open(saida_json, "w", encoding="utf-8") as fh:
                        json.dump(resultados, fh, indent=2, ensure_ascii=False)
                    # Feedback resumido
                    preview = resp[:80].replace("\n", " ") if resp else "(vazio)"
                    print(f" ok ({preview}...)")
                    time.sleep(1)

    print(f"\n[OK] Concluído. Resultados em {saida_json}")

if __name__ == "__main__":
    main()