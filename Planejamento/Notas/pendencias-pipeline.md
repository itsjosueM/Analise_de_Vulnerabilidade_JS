---
titulo: Pendências até o primeiro resultado do pipeline
data: 2026-11-21
tags:
  - "#pendencias"
  - "#github-actions"
---

# Contexto

No artigo original, o SAST roda no GitHub Actions, e os resultados de SAST deste projeto devem ser os do pipeline. Até ele rodar, **os números de SAST do `main.tex` ainda não vêm dele** e precisam ser substituídos.

# Como obter os resultados

1. Subir o repositório ao GitHub e abrir a aba **Actions → Benchmark SAST x LLM → Run workflow**.
2. O job `sast` roda sozinho (Semgrep 1.49.0 e SonarQube 25.5). Baixar o artefato `resultados-sast` para `resultados/sast/`.
3. Os LLMs não rodam no Actions: ficam locais via Ollama, e o job `analise` usa as respostas versionadas em `Lab/resultados/llm/`.
4. Baixar o artefato `resultados-analise` (ou rodar `python Lab/analisar_resultados.py` na pasta `Lab/` com `resultados/sast/` preenchido) e atualizar o artigo.

# O que atualizar no `../Artigo/main.tex` (fora do repositório) depois do pipeline

Tudo que depende de Semgrep ou SonarQube:

- Resumo e abstract: 30% de recall do Semgrep; "sempre acerta quando aponta algo".
- Seção 5 (RQ1): texto do Semgrep (6 de 20, 0 falsos positivos), do SonarQube (1 *vulnerability*, 18 *hotspots*, `insecurity.ts`, 2 falsos positivos) e a Tabela 2 (linhas Semgrep e SonarQube).
- Seção 6 (RQ2): lista de tipos do Semgrep e do SonarQube, Tabela 3 (linhas SAST) e Tabela 4 (Semgrep: 5,8 s; SonarQube: 58 itens, 57 *code smells*).
- Seção 7 (RQ3): conferência com o tipo esperado (Tabela 5, linhas Semgrep e SonarQube) e a frase sobre `server.ts`, `search-result.component.ts` e `app.routing.ts`.
- Seção 8 (RQ4): Tabela 7 inteira (SAST A/B e os híbridos) e o texto que a comenta.
- Limitações e conclusão: "F1 do SonarQube de 10% a 31%" e a conclusão sobre complementaridade.
- Remover o bloco `% PENDENTE` do início do arquivo.

Os números dos LLMs (Tabelas 2, 3, 4, 5 e parte da 7) não dependem do SAST e já estão corretos para as respostas versionadas.
