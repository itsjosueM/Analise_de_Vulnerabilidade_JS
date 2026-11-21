# Repetições do scan_llm.py (script sem alteração)

3 execuções do mesmo script, mesmo dataset, parâmetros padrão do Ollama (sem semente). Classificação com a mesma `extract_json`. Respostas de timeout (`{"erro": ...}`, leitura >300 s) ficam fora das contas: a `extract_json` as leria como JSON válido e as marcaria `vulnerable`.

## deepseek

| Execução | Precisão | Recall | F1 | VP | FP | FN | Marcados vulnerable | JSON válido | Timeouts (excluídos) |
|---|---|---|---|---|---|---|---|---|---|
| exec 1 | 67% | 90% | 77% | 18 | 9 | 2 | 27/30 | 13/30 | 0 |
| exec 2 | 74% | 85% | 79% | 17 | 6 | 3 | 23/30 | 11/30 | 0 |
| exec 3 | 64% | 80% | 71% | 16 | 9 | 4 | 25/30 | 10/30 | 0 |
| **média** | 68.2% | 85.0% | 75.6% | 17.0 | 8.0 | 3.0 | 25.0 | | |
| **desvio-padrão** | 4.2% | 4.1% | 3.3% | 0.8 | 1.4 | 0.8 | 1.6 | | |
| min–max F1 | 71%–79% | | | | | | | | |

- Arquivos com classificação diferente entre as execuções: **11/30**.
- Arquivos marcados `vulnerable` em todas as execuções: 19/30; entre eles, SAFE: 5/10.

## codellama

| Execução | Precisão | Recall | F1 | VP | FP | FN | Marcados vulnerable | JSON válido | Timeouts (excluídos) |
|---|---|---|---|---|---|---|---|---|---|
| exec 1 | 74% | 94% | 83% | 17 | 6 | 1 | 23/27 | 3/30 | 3 |
| exec 2 | 64% | 90% | 75% | 18 | 10 | 2 | 28/30 | 2/30 | 0 |
| exec 3 | 68% | 94% | 79% | 17 | 8 | 1 | 25/27 | 3/30 | 3 |
| **média** | 68.7% | 93.0% | 79.0% | 17.3 | 8.0 | 1.3 | 25.3 | | |
| **desvio-padrão** | 4.0% | 2.1% | 3.2% | 0.5 | 1.6 | 0.5 | 2.1 | | |
| min–max F1 | 75%–83% | | | | | | | | |

- Arquivos com classificação diferente entre as execuções: **7/30**.
- Arquivos marcados `vulnerable` em todas as execuções: 19/30; entre eles, SAFE: 4/10.
