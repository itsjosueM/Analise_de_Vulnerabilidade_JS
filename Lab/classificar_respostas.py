"""Classificação das respostas dos LLMs em `vulnerable` ou `safe`, a partir do texto cru gravado pelo scan_llm.py.

O prompt do artigo pede um JSON ou a frase "Código seguro"; as respostas em texto livre são classificadas pelo
que afirmam (nunca pelo rótulo VULN/SAFE do arquivo). Respostas de erro ({"erro": ...}, timeout de 300 s) não são
classificadas: classificar() devolve "sem_resposta" e elas ficam fora das contas.
"""
import json
import re

NEGACAO = re.compile(
    r"n[ãa]o h[áa] (nenhum[ao]s? )?(vulnerabilidade|riscos?)|"
    r"n[ãa]o (foram?|foi) (encontrad|identificad|detectad)\w* (nenhuma |qualquer )?vulnerabilidade|"
    r"n[ãa]o (cont[ée]m|possui|apresenta|tem)( nenhum[ao]?| qualquer| quaisquer)?( \w+){0,2} (vulnerabilidade|risco)|"
    r"(o )?c[óo]digo (est[áa]|[ée]) seguro|n[ãa]o (est[áa]|[ée]) vulner[áa]vel|"
    r"no vulnerabilit|does not (contain|have) any", re.I)
AFIRMA = re.compile(
    r"(cont[ée]m|possui|apresenta|tem)( v[áa]rias| algumas| as seguintes)? (vulnerabilidades|riscos)|"
    r"(vulnerabilidades?|riscos?)( de seguran[çc]a)?( foram| foi)? (encontrad|identificad|detectad)|"
    r"(encontrad|identificad|detectad)\w* (os |as )?(seguintes )?(riscos|vulnerabilidades)|"
    r"[ée] vulner[áa]vel|vulnerable to|is vulnerable|following (security )?(risks|vulnerabilities)|"
    r"aqui est[ãa]o (os )?riscos", re.I)
TERMOS = re.compile(r"vulnerab|injec|injeç|\bxss\b|csrf|ssrf|cross-site|ataque|exposi[çc][ãa]o|insegur|risco", re.I)


def primeiro_json(text):
    """Primeiro {...} balanceado que seja um JSON válido (testa todos os '{', não só o primeiro)."""
    pos = 0
    while True:
        start = text.find("{", pos)
        if start == -1:
            return None
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{": depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(text[start:i+1])
                        if isinstance(obj, dict): return obj
                    except json.JSONDecodeError: pass
                    break
        pos = start + 1

def extract_json(text):
    """Retorna (parsed, classification). classification ∈ vulnerable/safe; 'unparsed' só para resposta vazia."""
    if not text or not text.strip():
        return None, "unparsed"
    # 1) bloco ```json ... ```
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        try: return json.loads(m.group(1)), "vulnerable"
        except json.JSONDecodeError: pass
    # 2) algum {...} que seja JSON válido
    obj = primeiro_json(text)
    if obj is not None:
        return obj, "vulnerable"
    # 3) texto livre: responde "Código seguro" -> safe
    if text.strip().strip('"\'`*. ').lower().startswith(("código seguro", "codigo seguro")):
        return None, "safe"
    # 4) nega vulnerabilidades -> safe; afirma ou cita termos de vulnerabilidade -> vulnerable
    if NEGACAO.search(text): return None, "safe"
    if AFIRMA.search(text): return None, "vulnerable"
    if TERMOS.search(text): return None, "vulnerable"
    # 5) não aponta nenhuma vulnerabilidade -> pelo prompt, equivale a "Código seguro"
    return None, "safe"



def e_timeout(text):
    return text.lstrip().startswith('{"erro"')


def classificar(text):
    """Retorna (json_ou_None, 'vulnerable' | 'safe' | 'sem_resposta')."""
    if e_timeout(text):
        return None, "sem_resposta"
    return extract_json(text)
