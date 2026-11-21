"""Resume as execuções do scan_llm.py: Lab/resultados/llm/llm_results_exec*.json. Saída: resultados/repeticoes.md"""
import json
import statistics as st
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import classificar_respostas as E  # noqa: E402

LLM = RAIZ / "Lab" / "resultados" / "llm"
EXECS = {f"exec {i}": p for i, p in enumerate(sorted(LLM.glob("llm_results_exec*.json")), 1)}
dados = {k: json.loads(p.read_text(encoding="utf-8")) for k, p in EXECS.items()}


def metricas(pred):  # pred: {rel: True/False; None = timeout, fora das contas}
    resp = {r: v for r, v in pred.items() if v is not None}
    vp = sum(v for r, v in resp.items() if r.startswith("VULN/"))
    fp = sum(v for r, v in resp.items() if r.startswith("SAFE/"))
    n_vuln = sum(1 for r in resp if r.startswith("VULN/"))
    fn = n_vuln - vp
    p = vp / (vp + fp) if vp + fp else 0
    rc = vp / n_vuln if n_vuln else 0
    f = 2 * p * rc / (p + rc) if p + rc else 0
    return dict(p=p, r=rc, f=f, vp=vp, fp=fp, fn=fn, total=vp + fp, resp=len(resp))


md = ["# Repetições do scan_llm.py (script sem alteração)", "",
      str(len(EXECS)) + " execuções do mesmo script, mesmo dataset, parâmetros padrão do Ollama (sem semente). Classificação com a mesma `extract_json`. Respostas de timeout (`{\"erro\": ...}`, leitura >300 s) ficam fora das contas: a `extract_json` as leria como JSON válido e as marcaria `vulnerable`.", ""]
for chave in ("deepseek", "codellama"):
    md += [f"## {chave}", "", "| Execução | Precisão | Recall | F1 | VP | FP | FN | Marcados vulnerable | JSON válido | Timeouts (excluídos) |", "|---|---|---|---|---|---|---|---|---|---|"]
    preds, ms = {}, []
    for k, d in dados.items():
        pr, validos = {}, 0
        for rel, resp in d[chave].items():
            parsed, cls = E.extract_json(resp)
            timeout = resp.lstrip().startswith('{"erro"')
            pr[rel] = None if timeout else cls == "vulnerable"
            validos += parsed is not None and not timeout
        preds[k] = pr
        m = metricas(pr); ms.append(m)
        md.append(f"| {k} | {m['p']:.0%} | {m['r']:.0%} | {m['f']:.0%} | {m['vp']} | {m['fp']} | {m['fn']} | {m['total']}/{m['resp']} | {validos}/30 | {30 - m['resp']} |")
    for nome, fn_ in (("média", st.mean), ("desvio-padrão", st.pstdev)):
        md.append(f"| **{nome}** | {fn_([m['p'] for m in ms]):.1%} | {fn_([m['r'] for m in ms]):.1%} | {fn_([m['f'] for m in ms]):.1%} | "
                  f"{fn_([m['vp'] for m in ms]):.1f} | {fn_([m['fp'] for m in ms]):.1f} | {fn_([m['fn'] for m in ms]):.1f} | {fn_([m['total'] for m in ms]):.1f} | | |")
    md.append(f"| min–max F1 | {min(m['f'] for m in ms):.0%}–{max(m['f'] for m in ms):.0%} | | | | | | | | |")
    arqs = sorted(preds["exec 1"])
    inst = [a for a in arqs if len({preds[k][a] for k in preds} - {None}) > 1]
    sempre_v = [a for a in arqs if all(preds[k][a] for k in preds)]
    safe_sempre_v = [a for a in sempre_v if a.startswith("SAFE/")]
    md += ["", f"- Arquivos com classificação diferente entre as execuções: **{len(inst)}/30**.",
           f"- Arquivos marcados `vulnerable` em todas as execuções: {len(sempre_v)}/30; entre eles, SAFE: {len(safe_sempre_v)}/10.", ""]
(RAIZ / "resultados" / "repeticoes.md").write_text("\n".join(md), encoding="utf-8")
print("\n".join(md))
