"""Roda Semgrep 1.49.0 e SonarQube Community 25.5.0.107428 (scanner 11.3) em contêineres Docker sobre o dataset
original (Lab/dataset_sast). Este script é executado pelo pipeline do GitHub Actions (.github/workflows/benchmark.yml):
como no artigo original, os resultados de SAST do projeto são os do pipeline. Fora do Actions o script se recusa a
rodar, a menos que se passe --permitir-local; nesse caso o meta_sast.json registra a origem local e a análise
(analisar_resultados.py) rejeita esses resultados.

Saídas em resultados/sast/: semgrep.json, sonarqube_issues.json, sonarqube_hotspots.json, meta_sast.json (com a
identificação da execução: run id, commit, runner). As regras do Semgrep vêm do registro na data da execução (não
fixadas). O servidor do SonarQube é temporário (~2 GB de RAM); a senha de admin é aleatória e não é gravada."""
import argparse
import base64
import os
import json
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
DATASET = RAIZ / "Lab" / "dataset_sast"
SAIDA = RAIZ / "resultados" / "sast"

SEMGREP_IMG = "semgrep/semgrep:1.49.0"
SONAR_IMG = "sonarqube:25.5.0.107428-community"
SCANNER_IMG = "sonarsource/sonar-scanner-cli:11.3"
SONAR_CONTAINER = "sonar-benchmark"
SONAR_REDE = "sonar_net"
SONAR_HOST = "http://localhost:9099"   # porta do host (evita conflito com outros servicos)
PROJETO = "owasp-juice-shop-benchmark"


def docker(*args, **kw):
    return subprocess.run(["docker", *args], text=True, encoding="utf-8", errors="replace", **kw)


def semgrep():
    print("[*] Semgrep 1.49.0 sobre Lab/dataset_sast ...")
    SAIDA.mkdir(parents=True, exist_ok=True)
    (SAIDA / "semgrep.json").unlink(missing_ok=True)  # nunca aceitar resultado de execução anterior
    t0 = time.time()
    r = docker("run", "--rm", "-v", f"{DATASET}:/src:ro", "-v", f"{SAIDA}:/out",
               SEMGREP_IMG, "semgrep", "scan", "--config=p/typescript", "--config=p/javascript",
               "--metrics=off", "--json", "-o", "/out/semgrep.json", "/src",
               capture_output=True)
    dur = round(time.time() - t0, 1)
    saida = SAIDA / "semgrep.json"
    if not saida.exists():
        print(r.stdout[-1500:], r.stderr[-1500:])
        sys.exit("[!] Semgrep nao gerou semgrep.json")
    d = json.loads(saida.read_text(encoding="utf-8"))
    regras = sorted({x["check_id"] for x in d.get("results", [])})
    print(f"[✔] Semgrep: {len(d.get('results', []))} achados em {len(regras)} regras distintas "
          f"| erros: {len(d.get('errors', []))} | {dur}s")
    return {"semgrep": {"imagem": SEMGREP_IMG, "duracao_s": dur, "rc": r.returncode,
                        "achados": len(d.get("results", [])), "erros": len(d.get("errors", [])),
                        "configs": ["p/typescript", "p/javascript"]}}


def api(metodo, caminho, auth, dados=None, timeout=30):
    corpo = urllib.parse.urlencode(dados).encode() if dados is not None else None
    req = urllib.request.Request(SONAR_HOST + caminho, data=corpo, method=metodo)
    req.add_header("Authorization", "Basic " + base64.b64encode(auth.encode()).decode())
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        txt = resp.read().decode("utf-8")
    return json.loads(txt) if txt.strip() else {}


def sonarqube():
    print("[*] Subindo o SonarQube Community 25.5 (pode levar 1-3 min) ...")
    SAIDA.mkdir(parents=True, exist_ok=True)
    for antigo in ("sonarqube_issues.json", "sonarqube_hotspots.json"):
        (SAIDA / antigo).unlink(missing_ok=True)  # idem: sem reaproveitar saída antiga
    docker("rm", "-f", SONAR_CONTAINER, capture_output=True)
    docker("network", "create", SONAR_REDE, capture_output=True)
    r = docker("run", "-d", "--name", SONAR_CONTAINER, "--network", SONAR_REDE, "-p", "127.0.0.1:9099:9000",
               "-e", "SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true", SONAR_IMG, capture_output=True)
    if r.returncode != 0:
        sys.exit("[!] Falha ao iniciar o SonarQube: " + r.stderr[-500:])
    t0 = time.time()
    try:
        for _ in range(180):
            try:
                with urllib.request.urlopen(SONAR_HOST + "/api/system/status", timeout=5) as resp:
                    if json.loads(resp.read())["status"] == "UP":
                        break
            except Exception:
                pass
            time.sleep(3)
        else:
            sys.exit("[!] SonarQube nao ficou UP em 9 min.")
        print(f"    SonarQube UP em {round(time.time() - t0)}s")

        # senha inicial admin/admin e obrigatoriamente trocada; usamos uma senha aleatoria descartavel
        senha = secrets.token_urlsafe(18) + "Aa1!"
        api("POST", "/api/users/change_password", "admin:admin",
            {"login": "admin", "previousPassword": "admin", "password": senha})
        auth = f"admin:{senha}"
        token = api("POST", "/api/user_tokens/generate", auth, {"name": "benchmark"})["token"]

        print("[*] Rodando o sonar-scanner sobre Lab/dataset_sast ...")
        t1 = time.time()
        rs = docker("run", "--rm", "--network", SONAR_REDE, "-v", f"{DATASET}:/usr/src:ro",
                    "-e", f"SONAR_HOST_URL=http://{SONAR_CONTAINER}:9000", "-e", f"SONAR_TOKEN={token}",
                    SCANNER_IMG, "sonar-scanner", f"-Dsonar.projectKey={PROJETO}", "-Dsonar.sources=/usr/src",
                    "-Dsonar.exclusions=**/node_modules/**", "-Dsonar.scm.disabled=true",
                    capture_output=True)
        (SAIDA / "sonar_scanner.log").write_text((rs.stdout or "") + (rs.stderr or ""), encoding="utf-8")
        if rs.returncode != 0:
            sys.exit("[!] sonar-scanner falhou; veja resultados/sast/sonar_scanner.log\n" + (rs.stdout or "")[-1200:])

        # espera a tarefa de processamento no servidor (Compute Engine) terminar
        for _ in range(120):
            ce = api("GET", f"/api/ce/component?component={PROJETO}", auth)
            if not ce.get("queue") and ce.get("current", {}).get("status") in ("SUCCESS", "FAILED", "CANCELED"):
                break
            time.sleep(2)
        if ce.get("current", {}).get("status") != "SUCCESS":
            sys.exit("[!] Processamento no SonarQube nao terminou com SUCCESS: " + json.dumps(ce)[:300])
        dur_scan = round(time.time() - t1, 1)

        def paginar(caminho, chave, extra=""):
            itens, p = [], 1
            while True:
                d = api("GET", f"{caminho}?projectKey={PROJETO}&componentKeys={PROJETO}&ps=500&p={p}{extra}", auth)
                itens += d.get(chave, [])
                if p * 500 >= d.get("paging", {}).get("total", d.get("total", 0)):
                    return itens
                p += 1

        issues = paginar("/api/issues/search", "issues")
        hotspots = paginar("/api/hotspots/search", "hotspots")
        (SAIDA / "sonarqube_issues.json").write_text(json.dumps(issues, indent=2, ensure_ascii=False), encoding="utf-8")
        (SAIDA / "sonarqube_hotspots.json").write_text(json.dumps(hotspots, indent=2, ensure_ascii=False), encoding="utf-8")
        tipos = {}
        for i in issues:
            tipos[i["type"]] = tipos.get(i["type"], 0) + 1
        print(f"[✔] SonarQube: {len(issues)} issues {tipos} + {len(hotspots)} security hotspots | {dur_scan}s")
        return {"sonarqube": {"imagem": SONAR_IMG, "scanner": SCANNER_IMG, "duracao_analise_s": dur_scan,
                              "issues": len(issues), "tipos": tipos, "hotspots": len(hotspots)}}
    finally:
        docker("rm", "-f", SONAR_CONTAINER, capture_output=True)
        docker("network", "rm", SONAR_REDE, capture_output=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--so", choices=["semgrep", "sonarqube"], help="Roda apenas uma das ferramentas.")
    ap.add_argument("--permitir-local", action="store_true",
                    help="Permite rodar fora do GitHub Actions (resultado marcado como local e rejeitado pela análise).")
    args = ap.parse_args()
    no_actions = os.environ.get("GITHUB_ACTIONS") == "true"
    if not no_actions and not args.permitir_local:
        sys.exit("[!] Os resultados de SAST do projeto vêm do pipeline do GitHub Actions. Rode o workflow "
                 "'benchmark' (aba Actions) e baixe o artefato 'resultados-sast'.")
    meta = {"data": datetime.now().isoformat(timespec="seconds"), "dataset": str(DATASET.relative_to(RAIZ)),
            "n_arquivos": sum(1 for _ in DATASET.rglob("*.ts")),
            "github_actions": no_actions, "github_run_id": os.environ.get("GITHUB_RUN_ID"),
            "github_sha": os.environ.get("GITHUB_SHA"), "runner_os": os.environ.get("RUNNER_OS")}
    meta_arq = SAIDA / "meta_sast.json"
    if meta_arq.exists():  # preserva o que ja foi rodado ao usar --so
        antigo = json.loads(meta_arq.read_text(encoding="utf-8"))
        meta = {**antigo, **meta}
    if args.so in (None, "semgrep"):
        meta.update(semgrep())
    if args.so in (None, "sonarqube"):
        meta.update(sonarqube())
    SAIDA.mkdir(parents=True, exist_ok=True)
    meta_arq.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[✔] Metadados em {meta_arq}")


if __name__ == "__main__":
    main()
