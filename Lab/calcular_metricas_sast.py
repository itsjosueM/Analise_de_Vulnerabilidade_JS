#!/usr/bin/env python3
"""
calcular_metricas_sast.py
==========================
Calcula Precisão, Recall, F1 e FP Rate para Semgrep e SonarQube em NÍVEL DE ARQUIVO.

Ground truth disponível: apenas VULN vs SAFE (sem anotação por linha).
  VP = arquivo VULN com >=1 alerta
  FN = arquivo VULN sem nenhum alerta
  FP = arquivo SAFE com >=1 alerta
  TN = arquivo SAFE sem nenhum alerta

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
SAIDA        = RESULTADOS / "metricas_sast"
SAIDA.mkdir(parents=True, exist_ok=True)

# ---------- PARSERS ----------
def normalizar_path(p):
    p = p.replace("\\", "/")
    for marker in ("VULN/", "SAFE/"):
        idx = p.find(marker)
        if idx >= 0:
            return p[idx:]
    return p

def parse_semgrep(json_path):
    with open(json_path, encoding="utf-8") as f:
        data = json.load(f)
    alertas = defaultdict(list)
    for r in data.get("results", []):
        arq = normalizar_path(r.get("path", ""))
        ln  = (r.get("start") or {}).get("line")
        if arq and ln:
            alertas[arq].append(ln)
    return alertas

def parse_sonarqube(json_path):
    with open(json_path, encoding="utf-8") as f:
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

# ---------- MÉTRICAS (arquivo-nível) ----------
def calcular_arquivo_nivel(alertas, nome_ferramenta):
    VP = FN = FP = TN = 0
    detalhes = []

    for arq in sorted((DATASET_SAST / "VULN").glob("*.ts")):
        rel = f"VULN/{arq.name}"
        lines = alertas.get(rel, [])
        if lines:
            VP += 1; status = "VP"
        else:
            FN += 1; status = "FN"
        detalhes.append({"Ferramenta": nome_ferramenta, "Arquivo": rel,
                         "Status": status, "LinhasAlerta": lines})

    for arq in sorted((DATASET_SAST / "SAFE").glob("*.ts")):
        rel = f"SAFE/{arq.name}"
        lines = alertas.get(rel, [])
        if lines:
            FP += 1; status = "FP"
        else:
            TN += 1; status = "TN"
        detalhes.append({"Ferramenta": nome_ferramenta, "Arquivo": rel,
                         "Status": status, "LinhasAlerta": lines})

    precisao = VP / (VP + FP) if (VP + FP) > 0 else 0.0
    recall   = VP / (VP + FN) if (VP + FN) > 0 else 0.0
    f1       = 2 * precisao * recall / (precisao + recall) if (precisao + recall) > 0 else 0.0
    fp_rate  = FP / (VP + FP) if (VP + FP) > 0 else 0.0

    resumo = {
        "Ferramenta": nome_ferramenta,
        "VP": VP, "FP": FP, "FN": FN, "TN": TN,
        "Precisao": round(precisao, 4),
        "Recall":   round(recall, 4),
        "F1":       round(f1, 4),
        "FP_Rate":  round(fp_rate, 4),
    }
    return resumo, detalhes

# ---------- MAIN ----------
if __name__ == "__main__":
    ferramentas = []

    p = RESULTADOS / "semgrep" / "semgrep_raw.json"
    if p.exists():
        alertas = parse_semgrep(p)
        m, det = calcular_arquivo_nivel(alertas, "Semgrep")
        ferramentas.append(m)
        with open(SAIDA / "detalhes_semgrep.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Ferramenta","Arquivo","Status","LinhasAlerta"])
            for d in det:
                w.writerow([d["Ferramenta"], d["Arquivo"], d["Status"],
                            ";".join(map(str, d["LinhasAlerta"]))])
        print(f"✅ Semgrep processado — {sum(len(v) for v in alertas.values())} alertas em {len(alertas)} arquivos")
    else:
        print(f"⚠️  Não encontrado: {p}")

    p = RESULTADOS / "sonarqube" / "sonarqube_raw.json"
    if p.exists():
        alertas = parse_sonarqube(p)
        m, det = calcular_arquivo_nivel(alertas, "SonarQube")
        ferramentas.append(m)
        with open(SAIDA / "detalhes_sonarqube.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Ferramenta","Arquivo","Status","LinhasAlerta"])
            for d in det:
                w.writerow([d["Ferramenta"], d["Arquivo"], d["Status"],
                            ";".join(map(str, d["LinhasAlerta"]))])
        print(f"✅ SonarQube processado — {sum(len(v) for v in alertas.values())} alertas em {len(alertas)} arquivos")
    else:
        print(f"⚠️  Não encontrado: {p}")

    # Resumo (equivalente à Tabela 2)
    with open(SAIDA / "metricas_sast_resumo.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Ferramenta","VP","FP","FN","TN","Precisão","Recall","F1-Score","FP Rate"])
        for m in ferramentas:
            w.writerow([m["Ferramenta"], m["VP"], m["FP"], m["FN"], m["TN"],
                        f"{m['Precisao']*100:.0f}%", f"{m['Recall']*100:.0f}%",
                        f"{m['F1']*100:.0f}%", f"{m['FP_Rate']*100:.0f}%"])

    print(f"\n{'='*72}")
    print(f"{'Ferramenta':<12}{'VP':>4}{'FP':>4}{'FN':>4}{'TN':>4}{'Precisão':>11}{'Recall':>9}{'F1':>7}{'FP Rate':>10}")
    print("-" * 72)
    for m in ferramentas:
        print(f"{m['Ferramenta']:<12}{m['VP']:>4}{m['FP']:>4}{m['FN']:>4}{m['TN']:>4}"
              f"{m['Precisao']*100:>10.0f}%{m['Recall']*100:>8.0f}%"
              f"{m['F1']*100:>6.0f}%{m['FP_Rate']*100:>9.0f}%")
    print(f"{'='*72}\n")
    print(f"💾 Resultados salvos em: {SAIDA}")