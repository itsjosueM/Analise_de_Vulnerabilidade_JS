# Reprodução de artigo: SAST × LLMs na análise de código JavaScript

Reprodução do artigo **"Avaliação comparativa do desempenho de inteligências artificiais generativas e ferramentas tradicionais na análise de código-fonte JavaScript"** (Pimentel & Progetti, SBSeg 2025, WTICG). O artigo compara dois SAST (Semgrep, SonarQube) e dois LLMs (DeepSeek-Coder 1.3b, CodeLlama 7b) na detecção de vulnerabilidades no OWASP Juice Shop. O PDF está em `Planejamento/Artigo Original/`.

## Como reproduzir

Como no artigo original, **os resultados de SAST vêm do pipeline do GitHub Actions** (`.github/workflows/benchmark.yml`). O script `Lab/rodar_sast.py` recusa rodar fora do Actions, e `Lab/analisar_resultados.py` rejeita resultados de SAST que não tenham sido gerados lá.

### Pipeline (GitHub Actions): só o SAST

O workflow **Benchmark SAST x LLM** tem dois jobs e não faz commit de nada:

| Job | O que faz | Artefato |
|---|---|---|
| `sast` | Semgrep 1.49.0 (`p/typescript`, `p/javascript`) e SonarQube Community 25.5 (scanner 11.3) sobre `Lab/dataset_sast`; roda em todo push/PR e manualmente | `resultados-sast` |
| `analise` | depois do `sast`: métricas, tipos, conferência, filtro e híbrido (`analisar_resultados.py`) e variação entre execuções, usando as respostas dos LLMs versionadas em `Lab/resultados/llm/` | `resultados-analise` |

Para usar: abrir **Actions → Benchmark SAST x LLM → Run workflow** e, ao terminar, baixar os artefatos `resultados-sast` (para `resultados/sast/`) e `resultados-analise` (para `resultados/analise/` e `resultados/repeticoes.md`).

### LLMs: rodam localmente, via Ollama

Os LLMs não rodam no Actions. Com o Ollama instalado e os modelos baixados (`ollama pull codellama:7b` e `ollama pull deepseek-coder:1.3b`), rode `scan_llm.py` e salve cada execução como `Lab/resultados/llm/llm_results_exec<N>.json` (o script não usa semente, então as respostas variam). Rode também `teste_codigo_seguro.py`. Esses arquivos são versionados e o job `analise` usa todos os `llm_results_exec*.json`.

Versões usadas nas execuções versionadas: Ollama 0.40.16; `codellama:7b` (id `8fdf8f752f6e`, 3,8 GB) e `deepseek-coder:1.3b` (id `3ddd2d3fc8d2`, 776 MB).

### Scripts (rodar a partir de `Lab/`)

```bash
python diretiva_preprocessamento.py   # gera Lab/dataset_llm a partir de Lab/dataset_sast
python scan_llm.py                    # LLMs, local via Ollama (prompt do artigo + código) -> resultados/llm/llm_results.json
                                      # salvar cada execução como llm_results_exec<N>.json
python rodar_sast.py                  # Semgrep + SonarQube (só no Actions)
python analisar_resultados.py         # análise (SAST + LLM: classificação, métricas, tipos, filtro, híbrido) -> resultados/analise/
python resumo_repeticoes.py           # variação entre as execuções -> resultados/repeticoes.md
python teste_codigo_seguro.py         # local via Ollama; 3 trechos trivialmente seguros -> resultados/teste_codigo_seguro/
```

- **Dataset:** 30 arquivos (20 VULN + 10 SAFE) do Juice Shop v20.2.0 em `DataSet/` e `Lab/dataset_sast/` (originais, usados pelo SAST), idênticos aos do repositório do projeto. `Lab/dataset_llm/` é a cópia pré-processada que vai para os LLMs.
- **`classificar_respostas.py`:** converte cada resposta bruta em `vulnerable` ou `safe` (JSON válido → vulnerable; "Código seguro" → safe; texto livre pelo que afirma ou nega). Respostas de timeout (`{"erro": ...}`) ficam fora das contas.

## Resultados (30 arquivos, nível de arquivo, Código 2 do artigo)

LLMs: média das execuções do `scan_llm.py`, arredondada (timeouts de 300 s excluídos). Semgrep e SonarQube: resultados do pipeline do GitHub Actions (run `44862119143`, registrado em `resultados/sast/meta_sast.json`). Detalhes em `resultados/analise/analise_llm.md`.

| Ferramenta | Precisão | Recall | F1 | VP | FP | FN |
|---|---|---|---|---|---|---|
| Semgrep | 100% | 30% | 46% | 6 | 0 | 14 |
| SonarQube (só vulnerabilities) | 100% | 5% | 10% | 1 | 0 | 19 |
| SonarQube (vulnerabilities + hotspots) | 67% | 20% | 31% | 4 | 2 | 16 |
| DeepSeek-Coder | 68% | 85% | 76% | 17 | 8 | 3 |
| CodeLlama | 69% | 93% | 79% | 17 | 8 | 1 |

Referência do artigo (Tabela 2): Semgrep 100% / 50%, SonarQube 100% / 10%, DeepSeek 78% / 70%, CodeLlama 55% / 60% (precisão / recall). Não são diretamente comparáveis: o dataset aqui tem 30 arquivos, e não 15, e outra versão do Juice Shop.

**Como ler:** o padrão do artigo se repete (SAST com alta precisão e baixo recall; LLMs com recall alto e muitos falsos positivos), mas os LLMs marcam a maior parte dos arquivos como vulnerável (em média 25 de 30; 8 dos 10 SAFE), acertam o tipo esperado em 28% e 21% das citações e mudam de veredito entre execuções (11 arquivos do DeepSeek e 7 do CodeLlama). No teste com código trivialmente seguro (3 trechos × 3 execuções), foram classificados como vulnerable 6 de 9 respostas do DeepSeek e 4 de 9 do CodeLlama. O SonarQube depende do critério: com os hotspots, F1 31%; só com as vulnerabilities, 10%.

## Limitações a declarar

- **Pistas do rótulo:** o `scan_llm.py` não envia o nome do arquivo, mas 18 dos 20 VULN trazem no código nomes de desafio do Juice Shop (por exemplo `unionSqlInjectionChallenge`), contra 1 dos 10 SAFE.
- **A classificação das respostas é heurística** e não foi revisada à mão (o artigo não diz como tratou respostas fora do formato). Uma resposta que nega a vulnerabilidade no texto mas anexa o JSON é classificada como vulnerable (3 respostas do DeepSeek em uma execução).
- **Desvios do artigo:** Juice Shop v20.2.0 (artigo: v17.3.0); 30 arquivos (artigo: 15); `app.routing.ts` vem de uma versão ligeiramente mais nova.
- O `scan_llm.py` envia o exemplo de JSON do prompt com as chaves duplicadas (`{{`/`}}`), sem alteração por nossa parte; execuções sem semente; 6 chamadas do CodeLlama deram timeout (300 s) e foram excluídas; métrica em nível de arquivo (não verifica se o tipo apontado é o correto).

## Estrutura

```
Planejamento/   artigo original, BPMN, cronograma e notas
DataSet/        30 arquivos originais (VULN/ e SAFE/)
Lab/            scripts; dataset_sast/ (original), dataset_llm/ (pré-processado) e resultados/llm/ (saída bruta do scan_llm.py, uma por execução)
resultados/     repeticoes.md e teste_codigo_seguro/; sast/ e analise/ chegam como artefatos do pipeline
.github/        pipeline do GitHub Actions (benchmark.yml)
```

O artigo em LaTeX não faz parte deste repositório.

## Notas (`Planejamento/Notas/`)

| Nota | Conteúdo |
|---|---|
| `status-reproducao-e-diferenciais.md` | o que foi feito, o que falta e o diferencial |
