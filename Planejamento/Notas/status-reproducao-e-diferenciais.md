---
titulo: Status da reprodução — o que foi feito, o que falta e o diferencial
data: 2026-11-17
referencia: Pimentel & Progetti (2025), SBSeg 2025 (WTICG)
tags:
  - "#status"
  - "#reproducao-de-artigo"
---

# Resumo

O artigo compara Semgrep, SonarQube, DeepSeek-Coder 1.3b e CodeLlama 7b em arquivos do OWASP Juice Shop. A reprodução tem o caminho principal pronto (dataset, pré-processamento, LLMs, SAST e métricas no formato da Tabela 2). Faltam as análises qualitativas e por tipo de vulnerabilidade. Os LLMs marcam quase tudo como vulnerável, o que é o principal ponto a explicar na apresentação.

# 1. O que foi feito (caminho principal)

- [x] **Dataset:** 30 arquivos (20 VULN + 10 SAFE) do Juice Shop v20.2.0 (`DataSet/`, `Lab/dataset_sast/`). Três arquivos VULN vieram do repositório do Josué (`app.routing.ts`, `resetPassword.ts`, `updateUserProfile.ts`), o que cobre os 10 VULN da Tabela 1 do artigo.
- [x] **Pré-processamento:** `Lab/diretiva_preprocessamento.py` (corrigido: o regex original truncava URLs e apagava 14 linhas do `server.ts`; validado em 30 de 30 arquivos contra o scanner do TypeScript).
- [x] **LLMs:** `Lab/scan_llm.py` (do repositório do projeto) com o prompt do Código 1, CodeLlama 7b e DeepSeek-Coder 1.3b via Ollama, parâmetros padrão e sem o nome do arquivo. Execuções (sem semente): `Lab/resultados/llm/llm_results_exec<N>.json`.
- [x] **Classificação das respostas:** `Lab/classificar_respostas.py` (JSON válido → vulnerable; "Código seguro" → safe; texto livre pelo que afirma ou nega; timeout fora das contas).
- [x] **SAST pelo GitHub Actions:** `.github/workflows/benchmark.yml` (Semgrep 1.49.0 e SonarQube 25.5); resultados em `resultados/sast/` (run `44862119143`).
- [x] **Métricas, tipos, conferência, filtro e híbrido:** `Lab/analisar_resultados.py` → `resultados/analise/`; variação em `resultados/repeticoes.md`.
- [x] **Teste com código trivialmente seguro:** `Lab/teste_codigo_seguro.py` → `resultados/teste_codigo_seguro/`.
- [x] **Artigo no padrão SBC:** o artigo em LaTeX (fora do repositório).

# 2. Resultados (30 arquivos, nível de arquivo)

Os LLMs vêm do `scan_llm.py` do repositório do projeto (média das execuções, arredondada; timeouts excluídos).

| Ferramenta | Precisão | Recall | F1 | VP | FP | FN |
|---|---|---|---|---|---|---|
| Semgrep | 100% | 30% | 46% | 6 | 0 | 14 |
| SonarQube (só vulnerabilities) | 100% | 5% | 10% | 1 | 0 | 19 |
| SonarQube (vulnerabilities + hotspots) | 67% | 20% | 31% | 3 | 1 | 16 |
| DeepSeek-Coder  | 68 | 85 | 76 | 17 | 8 | 3 |
| CodeLlama  | 69 | 93 | 79 | 17 | 8 | 1 |

Marcação de arquivos SAFE como `vulnerable` (média): DeepSeek 8,0 de 10; CodeLlama 8,0 de ~10. Entre execuções, 11 (DeepSeek) e 7 (CodeLlama) arquivos mudam de classe. Arquivos: `resultados/analise/analise_llm.md`, `resultados/repeticoes.md`.

# 3. O que falta

| # | Pendência | Observação |
|---|---|---|
| 1 | Revisão manual de uma amostra da classificação dos LLMs (opcional) | A classificação é heurística e não foi revisada à mão; o artigo declara isso. |
| 2 | Gabarito de tipos validado para os 20 arquivos VULN (opcional) | A conferência de tipo usa só os 10 arquivos da Tabela 1 do artigo original. |

# 4. Limitações a declarar

- Pistas do rótulo: o nome do arquivo não é enviado aos LLMs, mas nomes de desafio do Juice Shop aparecem no código dos VULN (18 de 20, contra 1 de 10 SAFE).
- Classificação das respostas por heurística de texto, sem revisão manual; o artigo original não descreve esse passo.
- Desvios: Juice Shop v20.2.0 (artigo: v17.3.0), 30 arquivos (artigo: 15), `app.routing.ts` de versão mais nova.
- LLMs sem semente fixa (as respostas variam entre execuções), prompt do `scan_llm.py` com chaves duplicadas, 6 chamadas do CodeLlama com timeout; avaliação em nível de arquivo.

# 5. O diferencial (além do artigo)

- **Diagnóstico do comportamento dos LLMs:** os dois marcam em média 8 dos 10 arquivos SAFE, acertam o tipo esperado em 28% (DeepSeek) e 21% (CodeLlama) das citações e acusam vulnerabilidade em código trivialmente seguro (6 de 9 respostas do DeepSeek e 4 de 9 do CodeLlama).
- **Verificação de vazamento:** levantamento do que os LLMs recebem de pista do rótulo.
- **Correção do pré-processamento** e validação contra um parser real.
- **SonarQube com dois critérios** (só *vulnerabilities*, F1 10%; com *hotspots*, F1 31%).
- **Filtro de falsos positivos e híbrido SAST + LLM** (`Lab/analisar_resultados.py`).
