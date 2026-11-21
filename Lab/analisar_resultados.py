"""Análise dos resultados do scan_llm.py (todas as execuções em Lab/resultados/llm/) e do SAST: métricas (Código 2 do artigo), tipos reportados,
conferência com o tipo esperado, filtro de falsos positivos e pipeline híbrido. Os LLMs são reportados pela média
das execuções (o scan_llm.py não usa semente).

Timeouts do Ollama (`{"erro": ...}`) são "sem resposta": ficam fora das contas daquela execução.
Entradas: Lab/resultados/llm/llm_results_exec*.json, resultados/sast/ (artefato do GitHub Actions), Lab/dataset_llm/
Saída:    resultados/analise/analise_llm.json e analise_llm.md
Uso (a partir de Lab/):  python analisar_resultados.py"""
import json
import re
import statistics as st
from collections import Counter, defaultdict
from pathlib import Path

from sklearn.metrics import f1_score, precision_score, recall_score

from classificar_respostas import NEGACAO, classificar, e_timeout, primeiro_json

def calcular_metricas(y_true, y_pred):
    """Codigo 2 do artigo (SBSeg 2025), sem alteracoes de logica."""
    vp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)
    precisao = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    fp_rate = fp / (vp + fp) if (vp + fp) > 0 else 0
    return {"Precisao": precisao, "Recall": recall, "F1-Score": f1,
            "FP Rate": fp_rate, "VP": vp, "FP": fp, "FN": fn}


# Famílias de tipos para os LLMs (palavras-chave no texto da resposta).
FAMILIAS = {
    "Injeção (SQL/NoSQL/código)": r"inje[çc][ãa]o (de )?(sql|nosql|c[óo]digo|comando)|sql injection|nosql|command injection|code injection",
    "XSS": r"\bxss\b|cross-site scripting",
    "CSRF": r"csrf|cross-site request forgery",
    "Controle de acesso": r"controle de acesso|access control|autoriza[çc]|\bidor\b|insecure direct object",
    "Autenticação": r"autentica[çc]|authentication|brute force|for[çc]a bruta",
    "Exposição de dados": r"exposi[çc][ãa]o de (dados|informa)|sensitive|dados sens[íi]veis|informa[çc][õo]es sens[íi]veis|information disclosure|listagem de diret",
    "SSRF": r"ssrf|server-side request forgery",
    "Validação de entrada": r"valida[çc][ãa]o|input validation",
    "Upload/caminho de arquivo": r"upload|path traversal|travessia de diret",
    "Redirecionamento": r"redirect",
}

# Famílias para o SAST (por regra do Semgrep e por categoria/regra do SonarQube).
SEMGREP_FAMILIA = {
    "express-sequelize-injection": "Injeção (SQL/NoSQL/código)",
    "express-open-redirect": "Redirecionamento",
    "express-res-sendfile": "Upload/caminho de arquivo",
    "express-check-directory-listing": "Exposição de dados",
    "hardcoded-jwt-secret": "Credencial fixa",
}
SONAR_FAMILIA = {"xss": "XSS", "dos": "Negação de serviço (ReDoS/limites)", "weak-cryptography": "Criptografia fraca",
                 "insecure-conf": "Configuração insegura", "encrypt-data": "Protocolo sem criptografia (http)",
                 "others": "Outros"}

# Tipo esperado nos 10 arquivos VULN da Tabela 1 do artigo (família equivalente na nossa taxonomia).
TABELA1 = {
    "search-result.component.ts": "XSS",
    "login.ts": "Injeção (SQL/NoSQL/código)",
    "search.ts": "Injeção (SQL/NoSQL/código)",
    "updateProductReviews.ts": "Injeção (SQL/NoSQL/código)",   # NoSQL Injection no artigo
    "app.routing.ts": "Controle de acesso",
    "server.ts": "Exposição de dados",
    "profileImageUrlUpload.ts": "SSRF",
    "updateUserProfile.ts": "CSRF",
    "basketItems.ts": "Controle de acesso",
    "deluxe.ts": "Validação de entrada",
}

SQL_NO_CODIGO = re.compile(r"\.query\(|\.raw\(|\bSELECT\b|\bINSERT INTO\b|\bDELETE FROM\b|\bWHERE\b|\bUPDATE\b[^\n]*\bSET\b")
ALEGA_SQL = re.compile(r"inje[çc][ãa]o (de )?sql|sql injection|sqli", re.I)
ALEGA_OUTRO = re.compile(
    r"xss|cross-site|csrf|nosql|ssrf|redirect|traversal|idor|insecure direct|autoriza|autentica|controle de acesso|"
    r"access control|exposi|deserializ|upload|inje[çc][ãa]o de (c[óo]digo|comando|html|javascript|prompt)|"
    r"command injection|\beval\b", re.I)


def sem_espacos(s):
    return re.sub(r"\s+", "", s)


def trechos_citados(resposta):
    """"Trecho Vulnerável" (JSON) e código entre crases, ignorando blocos de código (exceto ```json)."""
    achados = []
    for bruto in re.findall(r'"Trecho Vulnerável"\s*:\s*"((?:[^"\\]|\\.)*)"', resposta):
        try:
            achados.append(json.loads('"' + bruto + '"'))
        except json.JSONDecodeError:
            achados.append(bruto)
    texto = []
    for i, parte in enumerate(resposta.split("```")):
        if i % 2 == 0:
            texto.append(parte)
        else:
            lang, _, corpo = parte.partition("\n")
            if lang.strip().lower() == "json":
                texto.append(corpo)
    achados += re.findall(r"`([^`\n]{4,200})`", " ".join(texto))
    return achados


def ancorado(trecho, codigo_sem_espacos):
    t = re.sub(r"\(\)$", "", sem_espacos(trecho))
    return len(t) >= 6 and t in codigo_sem_espacos


def decidir(resposta, codigo):
    cn = sem_espacos(codigo)
    citados = trechos_citados(resposta)
    ancorados = [t for t in citados if ancorado(t, cn)]
    so_sql = bool(ALEGA_SQL.search(resposta)) and not ALEGA_OUTRO.search(resposta)
    f1 = bool(ancorados)
    f2 = not (so_sql and not SQL_NO_CODIGO.search(codigo))
    return {"trechos_citados": len(citados), "trechos_ancorados": len(ancorados), "F1_ancorado": f1,
            "so_alega_sql": so_sql, "arquivo_tem_sql": bool(SQL_NO_CODIGO.search(codigo)), "F2_sql_ok": f2,
            "aprovado": f1 and f2}

LAB = Path(__file__).resolve().parent
RAIZ = LAB.parent
LLM = RAIZ / "Lab" / "resultados" / "llm"
EXECS = sorted(LLM.glob("llm_results_exec*.json"))
if not EXECS:
    raise SystemExit("[!] Nenhum Lab/resultados/llm/llm_results_exec*.json encontrado.")
SAST = RAIZ / "resultados" / "sast"
DATASET = RAIZ / "Lab" / "dataset_llm"
OUT = RAIZ / "resultados" / "analise"
MODELOS = {"deepseek": "deepseek-coder", "codellama": "codellama"}

rot = {f.name: p for p in ("VULN", "SAFE") for f in (DATASET / p).glob("*.ts")}
NOMES = sorted(rot)
CODIGO = {n: (DATASET / rot[n] / n).read_text(encoding="utf-8") for n in NOMES}


def nome(c):
    return c.replace("\\", "/").split(":")[-1].split("/")[-1]


# ---- SAST (mesmos dados já usados; Semgrep local = Semgrep do repositório)
_meta = SAST / "meta_sast.json"
if not _meta.exists() or not json.loads(_meta.read_text(encoding="utf-8")).get("github_actions"):
    raise SystemExit("[!] resultados/sast ausentes ou não vindos do GitHub Actions. Rode o workflow 'benchmark' "
                     "(aba Actions) e coloque o artefato 'resultados-sast' em resultados/sast/.")
achados = {"semgrep": defaultdict(list)}
for _r in json.loads((SAST / "semgrep.json").read_text(encoding="utf-8")).get("results", []):
    achados["semgrep"][nome(_r["path"])].append({"regra": _r["check_id"].split(".")[-1]})
sg = {n for n in NOMES if achados["semgrep"].get(n)}
issues = json.loads((SAST / "sonarqube_issues.json").read_text(encoding="utf-8"))
hot = json.loads((SAST / "sonarqube_hotspots.json").read_text(encoding="utf-8"))
son_vuln = {nome(i["component"]) for i in issues if i["type"] == "VULNERABILITY"}
son_hot = {nome(h["component"]) for h in hot}
SAST_PRED = {"Semgrep": sg, "SonarQube (só vulnerabilities)": son_vuln,
             "SonarQube (vulnerabilities + hotspots)": son_vuln | son_hot}

rel_sast = {"semgrep": {n: {SEMGREP_FAMILIA.get(a["regra"], a["regra"]) for a in achados["semgrep"].get(n, [])} for n in NOMES}}
sonar = defaultdict(set)
for i in issues:
    if i["type"] == "VULNERABILITY":
        sonar[nome(i["component"])].add("Credencial fixa")
for h in hot:
    sonar[nome(h["component"])].add(SONAR_FAMILIA.get(h["securityCategory"], h["securityCategory"]))
rel_sast["sonarqube"] = {n: sonar.get(n, set()) for n in NOMES}


def metr(pred_set, nomes):
    yt = [1 if rot[n] == "VULN" else 0 for n in nomes]
    return calcular_metricas(yt, [1 if n in pred_set else 0 for n in nomes])


def ms(x, pct=False, dec=1):
    m, s = st.mean(x), st.pstdev(x)
    return f"{100*m:.0f}% ± {100*s:.0f}" if pct else f"{m:.{dec}f} ± {s:.{dec}f}"


execs = []  # por execução: {modelo: {...}}
for caminho in EXECS:
    dados = json.loads(caminho.read_text(encoding="utf-8"))
    run = {}
    for chave in MODELOS:
        pred, rel, respostas, json_ok, contraditorias = {}, {}, {}, 0, 0
        for r, resp in dados[chave].items():
            n = r.split("/")[-1]
            if e_timeout(resp):
                continue  # timeout: sem resposta
            parsed, cls = classificar(resp)
            # JSON válido (regra 1 => vulnerable) em resposta que, no texto, nega haver vulnerabilidades
            contraditorias += primeiro_json(resp) is not None and bool(NEGACAO.search(resp))
            respostas[n] = resp
            pred[n] = cls == "vulnerable"
            json_ok += primeiro_json(resp) is not None
            rel[n] = {f for f, rx in FAMILIAS.items() if re.search(rx, resp, re.I)} if pred[n] else set()
        resp_nomes = sorted(pred)
        flag = {n for n in resp_nomes if pred[n]}
        # filtro
        filtrado, rej1, rej2 = set(), 0, 0
        for n in flag:
            d = decidir(respostas[n], CODIGO[n])
            rej1 += not d["F1_ancorado"]; rej2 += not d["F2_sql_ok"]
            if d["aprovado"]:
                filtrado.add(n)
        sastA = SAST_PRED["Semgrep"] | SAST_PRED["SonarQube (vulnerabilities + hotspots)"]
        sastB = SAST_PRED["Semgrep"] | SAST_PRED["SonarQube (só vulnerabilities)"]
        cfg = {"sem filtro": flag, "filtrado": filtrado,
               "híbrido A (Semgrep ou SonarQube com hotspots, ou LLM filtrado)": sastA | filtrado,
               "híbrido B (Semgrep ou SonarQube só vulnerabilities, ou LLM filtrado)": sastB | filtrado}
        met = {k: metr(v, resp_nomes) for k, v in cfg.items()}
        sast_ref = {"SAST A": metr(sastA, resp_nomes), "SAST B": metr(sastB, resp_nomes)}
        # tipos (tabela 3) e conferência com a Tabela 1
        t3 = {"VULN": Counter(), "SAFE": Counter()}
        for n in resp_nomes:
            for f in rel[n]:
                t3[rot[n]][f] += 1
        conf = {a: (fam in rel[a]) for a, fam in TABELA1.items() if a in rel}
        citados = sum(len(rel[a]) for a in conf)
        fams_vuln = [len(rel[n]) for n in flag]
        run[chave] = {
            "n_resp": len(resp_nomes), "timeouts": 30 - len(resp_nomes), "marcados": len(flag),
            "safe_marcados": sum(1 for n in flag if rot[n] == "SAFE"), "n_safe_resp": sum(1 for n in resp_nomes if rot[n] == "SAFE"),
            "json_valido": json_ok, "json_contraditorio": contraditorias, "metricas": met["sem filtro"], "cfg": met, "sast_ref": sast_ref,
            "rej_F1": rej1, "rej_F2": rej2,
            "t3": {k: dict(v) for k, v in t3.items()},
            "confere": sum(conf.values()), "confere_de": len(conf), "tipos_conf": citados,
            "tipos_medios": (sum(fams_vuln) / len(fams_vuln)) if fams_vuln else 0,
            "so_sql_sem_sql": sum(1 for n in flag if "Injeção (SQL/NoSQL/código)" in rel[n] and not SQL_NO_CODIGO.search(CODIGO[n])),
            "cita_sql": sum(1 for n in flag if "Injeção (SQL/NoSQL/código)" in rel[n]),
            "conf_por_arquivo": conf, "flag": sorted(flag), "rel": {n: sorted(v) for n, v in rel.items()},
        }
    execs.append(run)

# ---- agregação + relatório
md = ["# scan_llm.py: média das execuções", "",
      "Timeouts ficam fora das contas da execução. Híbridos avaliados nos arquivos com resposta do LLM.", ""]
agg = {}
cabec = "| Configuração | Precisão | Recall | F1 | FP Rate | VP | FP | FN |\n|---|---|---|---|---|---|---|---|"
md += ["## Métricas (Tabela 2)", "", cabec]
for k, conj in SAST_PRED.items():
    m = metr(conj, NOMES)
    md.append(f"| {k} | {m['Precisao']:.0%} | {m['Recall']:.0%} | {m['F1-Score']:.0%} | {m['FP Rate']:.0%} | {m['VP']} | {m['FP']} | {m['FN']} |")
    agg[k] = m
for chave, nm in MODELOS.items():
    L = [e[chave]["metricas"] for e in execs]
    md.append(f"| {nm} (média) | {ms([x['Precisao'] for x in L], True)} | {ms([x['Recall'] for x in L], True)} | {ms([x['F1-Score'] for x in L], True)} | "
              f"{ms([x['FP Rate'] for x in L], True)} | {ms([x['VP'] for x in L])} | {ms([x['FP'] for x in L])} | {ms([x['FN'] for x in L])} |")
    agg[nm] = {"por_execucao": L}
md += ["", "## Indicadores dos LLMs", "", "| Modelo | Marcados vulnerable (de resposta) | SAFE marcados | JSON válido | JSON que nega vulnerabilidade no texto | Timeouts | Tipos por resposta vulnerable | Cita injeção SQL | Cita injeção em arquivo sem SQL |", "|---|---|---|---|---|---|---|---|---|"]
for chave, nm in MODELOS.items():
    E_ = [e[chave] for e in execs]
    md.append(f"| {nm} | {ms([e['marcados'] for e in E_])} de {ms([e['n_resp'] for e in E_])} | {ms([e['safe_marcados'] for e in E_])} de ~10 | "
              f"{ms([e['json_valido'] for e in E_])}/30 | {[e['json_contraditorio'] for e in E_]} | {[e['timeouts'] for e in E_]} | {ms([e['tipos_medios'] for e in E_])} | {ms([e['cita_sql'] for e in E_])} | {ms([e['so_sql_sem_sql'] for e in E_])} |")
md += ["", "## Conferência com o tipo esperado (10 arquivos da Tabela 1)", "", "| Modelo | Arquivos que conferem | Tipos reportados | Precisão do tipo (por execução) |", "|---|---|---|---|"]
for chave, nm in MODELOS.items():
    E_ = [e[chave] for e in execs]
    pt = [e["confere"] / e["tipos_conf"] if e["tipos_conf"] else 0 for e in E_]
    md.append(f"| {nm} | {ms([e['confere'] for e in E_])} de ~10 | {ms([e['tipos_conf'] for e in E_])} | {ms(pt, True)} ({', '.join(f'{x:.0%}' for x in pt)}) |")
md += ["", "## Tipos reportados (média das execuções; nº de arquivos VULN de 20 / SAFE de 10)", ""]
for chave, nm in MODELOS.items():
    for cl in ("VULN", "SAFE"):
        tot = Counter()
        for e in execs:
            for f, v in e[chave]["t3"][cl].items():
                tot[f] += v / len(execs)
        md.append(f"- **{nm} {cl}**: " + ", ".join(f"{f} ({v:.1f})" for f, v in tot.most_common()))
md += ["", "## Filtro e híbrido (média das execuções)", "", cabec]
for k in ("SAST A", "SAST B"):
    L = [e["codellama"]["sast_ref"][k] for e in execs]
    md.append(f"| {k} ({'Semgrep ou SonarQube com hotspots' if k=='SAST A' else 'Semgrep ou SonarQube só vulnerabilities'}) | {ms([x['Precisao'] for x in L], True)} | {ms([x['Recall'] for x in L], True)} | {ms([x['F1-Score'] for x in L], True)} | {ms([x['FP Rate'] for x in L], True)} | {ms([x['VP'] for x in L])} | {ms([x['FP'] for x in L])} | {ms([x['FN'] for x in L])} |")
for chave, nm in MODELOS.items():
    for k in execs[0][chave]["cfg"]:
        L = [e[chave]["cfg"][k] for e in execs]
        md.append(f"| {nm}, {k} | {ms([x['Precisao'] for x in L], True)} | {ms([x['Recall'] for x in L], True)} | {ms([x['F1-Score'] for x in L], True)} | {ms([x['FP Rate'] for x in L], True)} | {ms([x['VP'] for x in L])} | {ms([x['FP'] for x in L])} | {ms([x['FN'] for x in L])} |")
    md.append(f"- {nm}: reprovadas pelo F1: {[e[chave]['rej_F1'] for e in execs]}; pelo F2: {[e[chave]['rej_F2'] for e in execs]}")
OUT.mkdir(parents=True, exist_ok=True)
(OUT / "analise_llm.md").write_text("\n".join(md), encoding="utf-8")
(OUT / "analise_llm.json").write_text(json.dumps({"execs": execs}, ensure_ascii=False, indent=1), encoding="utf-8")
print("\n".join(md))
