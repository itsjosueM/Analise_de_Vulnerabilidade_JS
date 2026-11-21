"""Teste com código trivialmente seguro: o mesmo prompt do scan_llm.py aplicado a três trechos sem superfície de
ataque, 3 execuções por modelo (o scan_llm.py não usa semente). Saída: resultados/teste_codigo_seguro/respostas.json
Uso (a partir de Lab/):  python teste_codigo_seguro.py"""
import json
from pathlib import Path

from classificar_respostas import classificar
from scan_llm import analisar

TRECHOS = {
    "soma": "export function soma (a: number, b: number): number {\n  return a + b\n}\n",
    "constantes": "export const LIMITE_ITENS = 20\nexport const NOME_APP = 'loja'\nexport const VERSAO = 3\n",
    "ehPar": "export function ehPar (n: number): boolean {\n  return n % 2 === 0\n}\n",
}
MODELOS = {"deepseek": "deepseek-coder:1.3b", "codellama": "codellama:7b"}
EXECUCOES = 3

saida = {}
for chave, modelo in MODELOS.items():
    saida[chave] = {}
    for nome, codigo in TRECHOS.items():
        saida[chave][nome] = []
        for e in range(EXECUCOES):
            resp = analisar(modelo, codigo)
            saida[chave][nome].append({"resposta": resp, "classificacao": classificar(resp)[1]})
            print(chave, nome, e + 1, saida[chave][nome][-1]["classificacao"], flush=True)
destino = Path(__file__).resolve().parent.parent / "resultados" / "teste_codigo_seguro"
destino.mkdir(parents=True, exist_ok=True)
(destino / "respostas.json").write_text(json.dumps({"trechos": TRECHOS, "respostas": saida}, ensure_ascii=False, indent=1), encoding="utf-8")
resumo = {c: {n: sum(1 for r in v if r["classificacao"] == "vulnerable") for n, v in d.items()} for c, d in saida.items()}
print("vulnerable por trecho (de", EXECUCOES, "execuções):", resumo)
