#!/usr/bin/env python3
"""
calcular_metricas_comparativo.py
=================================
Calcula Precisão, Recall, F1 e FP Rate para Semgrep, SonarQube e DeepSeek
em NÍVEL DE ARQUIVO (ground truth disponível: VULN vs SAFE).

Classificação LLM:
  vulnerable / vulnerable_textonly → conta como ALERTA
  safe / unparsed                  → conta como SEM ALERTA

Fórmulas (Eqs. 1–4 do artigo):
  Precisão = VP / (VP + FP)
  Recall   = VP / (VP + FN)
  F1       = 2*P*R / (P+R)
  FP Rate  = FP / (VP + FP)
"""
import json
import csv
from pathlib import Path
from collections import defaultdict

LAB          = Path(__file__).parent
DATASET_SAST = LAB / "dataset_sast"
RESULTADOS   = LAB / "resultados"
SAIDA        = RESULTADOS / "metricas_comparativo"
SAIDA.mkdir(parents=True, exist_ok=True)

# ---------- PARSERS ----------
def normalizar_path(p):
    p = p.replace("\\", "/")
    for marker in ("VULN/", "SAFE/"):
        idx = p.find(marker)
        if idx >= 0:
            return p[idx:]
    return p

def parse_semgrep(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    alertas = defaultdict(list)
    for r in data.get("results", []):
        arq = normalizar_path(r.get("path", ""))
        ln  = (r.get("start") or {}).get("line")
        if arq and ln:
            alertas[arq].append(ln)
    return alertas

def parse_sonarqube(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    alertas = defaultdict(list)
    for issue in data.get("issues", []):
        comp = issue.get("component", "")
        arq  = normalizar_path(comp.split(":", 1)[1] if ":" in comp else comp)
        tr   = issue.get("textRange") or {}
        ln   = tr.get("startLine") or issue.get("line")
        if arq and ln:
            alertas[arq].append(ln)
    return alertas

def parse_llm(path):
    """Retorna { 'VULN/arq.ts': [pseudo-linha] } para arquivos sinalizados."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    alertas = defaultdict(list)
    for r in data.get("results", []):
        if r.get("classification") in ("vulnerable", "vulnerable_textonly"):
            alertas[r["file"]].append("sinalizado")  # pseudo-linha
    return alertas

# ---------- MÉTRICAS ----------
def calcular(alertas, nome, categoria_ferramenta):
    VP = FN = FP = TN = 0
    detalhes = []

    for arq in sorted((DATASET_SAST / "VULN").glob("*.ts")):
        rel = f"VULN/{arq.name}"
        hit = alertas.get(rel, [])
        status = "VP" if hit else "FN"
        VP += 1 if hit else 0
        FN += 0 if hit else 1
        detalhes.append({"Ferramenta": nome, "Categoria": categoria_ferramenta,
                         "Arquivo": rel, "Status": status,
                         "Alertas": ";".join(map(str, hit))})

    for arq in sorted((DATASET_SAST / "SAFE").glob("*.ts")):
        rel = f"SAFE/{arq.name}"
        hit = alertas.get(rel, [])
        status = "FP" if hit else "TN"
        FP += 1 if hit else 0
        TN += 0 if hit else 1
        detalhes.append({"Ferramenta": nome, "Categoria": categoria_ferramenta,
                         "Arquivo": rel, "Status": status,
                         "Alertas": ";".join(map(str, hit))})

    precisao = VP / (VP + FP) if (VP + FP) > 0 else 0.0
    recall   = VP / (VP + FN) if (VP + FN) > 0 else 0.0
    f1       = 2 * precisao * recall / (precisao + recall) if (precisao + recall) > 0 else 0.0
    fp_rate  = FP / (VP + FP) if (VP + FP) > 0 else 0.0

    resumo = {
        "Ferramenta": nome, "Tipo": categoria_ferramenta,
        "VP": VP, "FP": FP, "FN": FN, "TN": TN,
        "Precisao": round(precisao, 4), "Recall": round(recall, 4),
        "F1": round(f1, 4), "FP_Rate": round(fp_rate, 4),
    }
    return resumo, detalhes

# ---------- MAIN ----------
if __name__ == "__main__":
    ferramentas, detalhes_todos = [], []

    configs = [
        ("Semgrep",   "SAST", RESULTADOS / "semgrep"   / "semgrep_raw.json",   parse_semgrep),
        ("SonarQube", "SAST", RESULTADOS / "sonarqube" / "sonarqube_raw.json", parse_sonarqube),
        ("DeepSeek",  "LLM",  RESULTADOS / "llm"       / "deepseek_raw.json",  parse_llm),
        ("CodeLlama", "LLM",  RESULTADOS / "llm"       / "codellama_raw.json", parse_llm),
    ]

    for nome, tipo, path, parser in configs:
        if not path.exists():
            print(f"⚠️  {nome:<10} — arquivo não encontrado: {path.name}")
            continue
        alertas = parser(path)
        n_alertas = sum(len(v) for v in alertas.values())
        print(f"✅ {nome:<10} — {n_alertas} alertas em {len(alertas)} arquivos")
        m, det = calcular(alertas, nome, tipo)
        ferramentas.append(m)
        detalhes_todos.extend(det)

    # CSV detalhado
    with open(SAIDA / "detalhes_por_arquivo.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["Ferramenta","Categoria","Arquivo","Status","Alertas"])
        w.writeheader()
        w.writerows(detalhes_todos)

    # CSV resumo (Tabela 2 do artigo)
    with open(SAIDA / "tabela2_resumo.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Ferramenta","Tipo","VP","FP","FN","TN","Precisão","Recall","F1-Score","FP Rate"])
        for m in ferramentas:
            w.writerow([m["Ferramenta"], m["Tipo"], m["VP"], m["FP"], m["FN"], m["TN"],
                        f"{m['Precisao']*100:.0f}%", f"{m['Recall']*100:.0f}%",
                        f"{m['F1']*100:.0f}%", f"{m['FP_Rate']*100:.0f}%"])

    # Print no console
    print(f"\n{'='*88}")
    print(f"{'Ferramenta':<12}{'Tipo':<6}{'VP':>4}{'FP':>4}{'FN':>4}{'TN':>4}"
          f"{'Precisão':>11}{'Recall':>9}{'F1':>7}{'FP Rate':>10}")
    print("-" * 88)
    for m in ferramentas:
        print(f"{m['Ferramenta']:<12}{m['Tipo']:<6}{m['VP']:>4}{m['FP']:>4}{m['FN']:>4}{m['TN']:>4}"
              f"{m['Precisao']*100:>10.0f}%{m['Recall']*100:>8.0f}%"
              f"{m['F1']*100:>6.0f}%{m['FP_Rate']*100:>9.0f}%")
    print(f"{'='*88}\n")
    print(f"💾 Resultados salvos em: {SAIDA}")
    print(f"   → tabela2_resumo.csv")
    print(f"   → detalhes_por_arquivo.csv")