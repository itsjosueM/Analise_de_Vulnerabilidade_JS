# Lab/teste.py
import requests
from scan_llm import montar_prompt

with open("dataset_llm/VULN/2fa.ts", encoding="utf-8") as f:
    codigo = f.read()

r = requests.post(
    "http://localhost:11434/api/generate",
    json={"model": "deepseek-coder:1.3b", "prompt": montar_prompt(codigo), "stream": False},
    timeout=300
)
print(r.json().get("response"))