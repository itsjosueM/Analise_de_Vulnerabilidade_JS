#!/usr/bin/env python3
"""
executar_llm.py
================
Executa DeepSeek-Coder e CodeLlama localmente via Ollama para detecção de
vulnerabilidades no dataset do OWASP Juice Shop.

Baseado no prompt do Código 1 do artigo (Pimentel & Progetti, 2025).

Uso:
    python executar_llm.py --model deepseek
    python executar_llm.py --model codellama
    python executar_llm.py --model all
"""
import argparse
import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path

import requests

OLLAMA_URL     = "http://localhost:11434/api/generate"
OLLAMA_TAGS    = "http://localhost:11434/api/tags"
MODELS         = {"deepseek": "deepseek-coder:1.3b", "codellama": "codellama:7b"}
DATASET_DIR    = Path(__file__).parent / "dataset_llm"
RESULTS_DIR    = Path(__file__).parent / "resultados" / "llm"
REQUEST_TIMEOUT = 900  # 15 min por arquivo
GEN_OPTIONS    = {"temperature": 0, "seed": 42, "num_predict": 1024, "top_p": 1.0}

PROMPT_HEADER = """Analise os riscos de segurança no código abaixo, seguindo o OWASP Top 10. Retorne APENAS se houver vulnerabilidades, no formato JSON abaixo. Caso contrário, retorne "Código seguro".

{
  "Arquivo": "Nome do arquivo",
  "Trecho Vulnerável": "O snippet de código específico que contém a vulnerabilidade.",
  "Tipo da Vulnerabilidade": "A categoria da vulnerabilidade",
  "Descrição Breve": "Uma explicação concisa (1-2 frases) de por que esse trecho é vulnerável"
}
"""

def build_prompt(filename, code):
    return f"{PROMPT_HEADER}\nArquivo: {filename}\n\nCódigo:\n```typescript\n{code}\n```"

def check_ollama(required_models):
    try:
        r = requests.get(OLLAMA_TAGS, timeout=10); r.raise_for_status()
    except requests.exceptions.ConnectionError:
        print("❌ Ollama não está rodando. Execute em outro terminal: ollama serve"); sys.exit(1)
    available = {m["name"] for m in r.json().get("models", [])}
    missing = [m for m in required_models if m not in available]
    if missing:
        print(f"❌ Modelos ausentes: {missing}\n   Baixe: ollama pull <modelo>"); sys.exit(1)
    print(f"✅ Ollama OK — modelos: {required_models}")

def collect_files():
    out = []
    for cat in ("VULN", "SAFE"):
        d = DATASET_DIR / cat
        if not d.exists():
            print(f"❌ Diretório não encontrado: {d}"); sys.exit(1)
        for f in sorted(d.glob("*.ts")):
            out.append((cat, f))
    return out

def call_ollama(model, prompt):
    r = requests.post(OLLAMA_URL, json={
        "model": model, "prompt": prompt, "stream": False, "options": GEN_OPTIONS,
    }, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    return r.json().get("response", "")

def extract_json(text):
    """Retorna (parsed, classification). classification ∈ vulnerable/safe/unparsed."""
    if not text or not text.strip():
        return None, "unparsed"
    # 1) bloco ```json ... ```
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        try: return json.loads(m.group(1)), "vulnerable"
        except json.JSONDecodeError: pass
    # 2) primeiro {...} balanceado
    start = text.find("{")
    if start != -1:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{": depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try: return json.loads(text[start:i+1]), "vulnerable"
                    except json.JSONDecodeError: break
    # 3) heurística de segurança
    if "código seguro" in text.lower() or "codigo seguro" in text.lower():
        return None, "safe"
    return None, "unparsed"

def run_model(key):
    model = MODELS[key]
    print(f"\n{'='*70}\n🤖 {key} ({model})\n{'='*70}")
    check_ollama([model])
    files = collect_files()
    print(f"📁 {len(files)} arquivos · iniciando...\n")

    results = []
    for i, (cat, path) in enumerate(files, 1):
        rel = f"{cat}/{path.name}"
        print(f"[{i:02d}/{len(files)}] {rel:<55}", end=" ", flush=True)
        code = path.read_text(encoding="utf-8", errors="replace")
        prompt = build_prompt(path.name, code)
        t0 = time.time()
        try:
            raw = call_ollama(model, prompt)
            parsed, cls = extract_json(raw)
            dt = time.time() - t0
            icon = {"vulnerable":"🔴","safe":"🟢","unparsed":"⚠️"}[cls]
            print(f"{icon} {cls} ({dt:.1f}s)")
            results.append({"file": rel, "category": cat, "raw_response": raw,
                            "parsed": parsed, "classification": cls,
                            "duration_seconds": round(dt,2), "error": None})
        except Exception as e:
            dt = time.time() - t0
            print(f"❌ {e}")
            results.append({"file": rel, "category": cat, "raw_response": None,
                            "parsed": None, "classification": "unparsed",
                            "duration_seconds": round(dt,2), "error": str(e)})

    stats = {k: sum(1 for r in results if r["classification"]==k)
             for k in ("vulnerable","safe","unparsed")}
    stats["errors"] = sum(1 for r in results if r["error"])

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = RESULTS_DIR / f"{key}_raw.json"
    out.write_text(json.dumps({
        "model": model, "model_key": key,
        "finished_at": datetime.now().isoformat(),
        "total_files": len(files), "statistics": stats, "results": results,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"\n✅ {key}: {stats}")
    print(f"💾 Salvo em: {out}\n")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--model", choices=["deepseek","codellama","all"], required=True)
    a = p.parse_args()
    if a.model == "all":
        run_model("deepseek"); run_model("codellama")
    else:
        run_model(a.model)