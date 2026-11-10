import json, time, requests
from pathlib import Path

MODEL = "deepseek-coder:1.3b"

PROMPT = """Analise os riscos de segurança no código abaixo, seguindo o OWASP Top 10. Retorne APENAS se houver vulnerabilidades, no formato JSON abaixo. Caso contrário, retorne "Código seguro".

{
  "Arquivo": "Nome do arquivo",
  "Trecho Vulnerável": "O snippet de código específico que contém a vulnerabilidade.",
  "Tipo da Vulnerabilidade": "A categoria da vulnerabilidade",
  "Descrição Breve": "Uma explicação concisa (1-2 frases) de por que esse trecho é vulnerável"
}
"""

# 4 arquivos com vulnerabilidades MUITO óbvias
ARQUIVOS = [
    "dataset_llm/VULN/search-result.component.ts",   # DOM XSS (innerHTML)
    "dataset_llm/VULN/basketItems.ts",                # Broken Access Control
    "dataset_llm/VULN/fileServer.ts",                 # Path Traversal
    "dataset_llm/VULN/updateProductReviews.ts",       # NoSQL Injection
]

for arq in ARQUIVOS:
    p = Path(arq)
    codigo = p.read_text(encoding="utf-8")
    prompt = f"{PROMPT}\nArquivo: {p.name}\n\nCódigo:\n```typescript\n{codigo}\n```"
    t0 = time.time()
    r = requests.post("http://localhost:11434/api/generate", json={
        "model": MODEL, "prompt": prompt, "stream": False,
        "options": {"temperature": 0, "seed": 42, "num_predict": 1024},
    }, timeout=600)
    dt = time.time() - t0
    resposta = r.json().get("response", "")
    
    detectou = "{" in resposta  # heurística simples
    status = "🔴 DETECTOU" if detectou else "🟢 disse 'seguro'"
    print(f"\n{'='*70}\n{p.name} — {status} ({dt:.0f}s)\n{'='*70}")
    print(resposta[:800])