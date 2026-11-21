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
- [ ] **SAST pelo GitHub Actions:** pipeline `.github/workflows/benchmark.yml` pronto (Semgrep 1.49.0 e SonarQube 25.5); falta executá-lo e baixar o artefato `resultados-sast`.
- [x] **Métricas, tipos, conferência, filtro e híbrido:** `Lab/analisar_resultados.py` → `resultados/analise/`; variação em `resultados/repeticoes.md`.
- [x] **Teste com código trivialmente seguro:** `Lab/teste_codigo_seguro.py` → `resultados/teste_codigo_seguro/`.
- [x] **Artigo no padrão SBC:** `../Artigo/main.tex` (fora do repositório).

# 2. Resultados (30 arquivos, nível de arquivo)

**As linhas de SAST abaixo ainda não vêm do pipeline**; ver `pendencias-pipeline.md`. Os LLMs vêm do `scan_llm.py` do repositório do projeto (média das execuções, arredondada; timeouts excluídos).

| Ferramenta | Precisão | Recall | F1 | VP | FP | FN |
|---|---|---|---|---|---|---|
| Semgrep | 100% | 30% | 46% | 6 | 0 | 14 |
| SonarQube (só vulnerabilities) | 100% | 5% | 10% | 1 | 0 | 19 |
| SonarQube (vulnerabilities + hotspots) | 67% | 20% | 31% | 4 | 2 | 16 |
| DeepSeek-Coder  | 68 | 85 | 76 | 17 | 8 | 3 |
| CodeLlama  | 69 | 93 | 79 | 17 | 8 | 1 |

Marcação de arquivos SAFE como `vulnerable` (média): DeepSeek 8,0 de 10; CodeLlama 8,0 de ~10. Entre execuções, 11 (DeepSeek) e 7 (CodeLlama) arquivos mudam de classe. Arquivos: `resultados/analise/analise_llm.md`, `resultados/repeticoes.md`.

# 3. O que falta

| # | Pendência | Observação |
|---|---|---|
| 1 | Gabarito de tipos validado para os 20 arquivos VULN | A Tabela 3 não depende dele; a conferência de tipo usa só os 10 arquivos da Tabela 1 do artigo original. |
| 2 | Preencher autores e instituição e revisar o texto do artigo | Há marcadores `[Instituição]`, `[sobrenome]` e `[e-mail dos autores]` em `../Artigo/main.tex` (fora do repositório). |
| 3 | **Revisão da classificação dos LLMs** (opcional) | Os casos menos firmes estão em `nota-classification-executar-llm.md`. |
| 4 | Refazer o DAST (extensão) com o dataset atual | Os resultados guardados são do dataset anterior. |
| 5 | Commits | Quase tudo está sem commit. |

# 4. Limitações a declarar

- Pistas do rótulo na entrada dos LLMs: nome do arquivo (`_correct`) e nomes de desafio no código dos VULN. Vem do desenho do artigo.
- Classificação das respostas por heurística de texto; o artigo não descreve esse passo.
- Desvios: Juice Shop v20.2.0 (artigo: v17.3.0), 30 arquivos (artigo: 15), `app.routing.ts` de versão mais nova. SAST pelo GitHub Actions, como no original.
- Uma execução; nível de arquivo.

# 5. O diferencial (além do artigo)

- **Diagnóstico do comportamento dos LLMs:** o CodeLlama aponta vulnerabilidade até em código trivialmente seguro (testado com uma soma e um arquivo de constantes) e cita SQL injection em arquivos sem SQL (9 respostas). O DeepSeek consegue dizer "seguro" nos casos triviais, mas marca 9 dos 10 SAFE reais.
- **Verificação de vazamento:** levantamento do que os LLMs recebem de pista do rótulo.
- **Correção do pré-processamento** e validação contra um parser real.
- **Extensões (fora do caminho principal):** filtro de falsos positivos e híbrido SAST + LLM (`Lab/analisar_resultados.py`, depois do pipeline) e DAST com OWASP ZAP (`../Analise_Dinamica_DAST/`, `../Planejamento_notas_extras/nota-dast-etapa-a.md`, fora do projeto).
