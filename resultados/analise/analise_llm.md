# scan_llm.py: média das execuções

Timeouts ficam fora das contas da execução. Híbridos avaliados nos arquivos com resposta do LLM.

## Métricas (Tabela 2)

| Configuração | Precisão | Recall | F1 | FP Rate | VP | FP | FN |
|---|---|---|---|---|---|---|---|
| Semgrep | 100% | 30% | 46% | 0% | 6 | 0 | 14 |
| SonarQube (só vulnerabilities) | 100% | 5% | 10% | 0% | 1 | 0 | 19 |
| SonarQube (vulnerabilities + hotspots) | 67% | 20% | 31% | 33% | 4 | 2 | 16 |
| deepseek-coder (média) | 68% ± 4 | 85% ± 4 | 76% ± 3 | 32% ± 4 | 17.0 ± 0.8 | 8.0 ± 1.4 | 3.0 ± 0.8 |
| codellama (média) | 69% ± 4 | 93% ± 2 | 79% ± 3 | 31% ± 4 | 17.3 ± 0.5 | 8.0 ± 1.6 | 1.3 ± 0.5 |

## Indicadores dos LLMs

| Modelo | Marcados vulnerable (de resposta) | SAFE marcados | JSON válido | JSON que nega vulnerabilidade no texto | Timeouts | Tipos por resposta vulnerable | Cita injeção SQL | Cita injeção em arquivo sem SQL |
|---|---|---|---|---|---|---|---|---|
| deepseek-coder | 25.0 ± 1.6 de 30.0 ± 0.0 | 8.0 ± 1.4 de ~10 | 11.3 ± 1.2/30 | [3, 0, 0] | [0, 0, 0] | 1.7 ± 0.2 | 9.0 ± 2.4 | 8.0 ± 1.6 |
| codellama | 25.3 ± 2.1 de 28.0 ± 1.4 | 8.0 ± 1.6 de ~10 | 2.7 ± 0.5/30 | [0, 0, 0] | [3, 0, 3] | 3.5 ± 0.0 | 16.3 ± 1.7 | 13.7 ± 1.9 |

## Conferência com o tipo esperado (10 arquivos da Tabela 1)

| Modelo | Arquivos que conferem | Tipos reportados | Precisão do tipo (por execução) |
|---|---|---|---|
| deepseek-coder | 4.3 ± 1.7 de ~10 | 14.7 ± 2.6 | 28% ± 8 (38%, 18%, 29%) |
| codellama | 7.0 ± 0.8 de ~10 | 34.3 ± 2.5 | 21% ± 3 (16%, 23%, 23%) |

## Tipos reportados (média das execuções; nº de arquivos VULN de 20 / SAFE de 10)

- **deepseek-coder VULN**: Autenticação (7.3), Injeção (SQL/NoSQL/código) (5.3), Controle de acesso (4.3), Validação de entrada (3.7), XSS (3.7), Exposição de dados (2.7), CSRF (2.0), Upload/caminho de arquivo (1.3), Redirecionamento (1.0), SSRF (0.7)
- **deepseek-coder SAFE**: Injeção (SQL/NoSQL/código) (3.7), Validação de entrada (2.0), Controle de acesso (1.3), Autenticação (1.3), XSS (0.7), Redirecionamento (0.7), CSRF (0.3), Exposição de dados (0.3)
- **codellama VULN**: Injeção (SQL/NoSQL/código) (11.7), XSS (9.3), Exposição de dados (9.3), Controle de acesso (7.7), Autenticação (7.0), Validação de entrada (7.0), Redirecionamento (5.0), CSRF (4.7), Upload/caminho de arquivo (1.7), SSRF (0.3)
- **codellama SAFE**: Exposição de dados (4.7), Injeção (SQL/NoSQL/código) (4.7), XSS (3.7), Controle de acesso (3.0), Autenticação (2.7), Redirecionamento (2.3), Validação de entrada (2.0), CSRF (1.7), Upload/caminho de arquivo (0.7)

## Filtro e híbrido (média das execuções)

| Configuração | Precisão | Recall | F1 | FP Rate | VP | FP | FN |
|---|---|---|---|---|---|---|---|
| SAST A (Semgrep ou SonarQube com hotspots) | 79% ± 1 | 39% ± 1 | 52% ± 1 | 21% ± 1 | 7.3 ± 0.5 | 2.0 ± 0.0 | 11.3 ± 0.5 |
| SAST B (Semgrep ou SonarQube só vulnerabilities) | 100% ± 0 | 29% ± 1 | 44% ± 1 | 0% ± 0 | 5.3 ± 0.5 | 0.0 ± 0.0 | 13.3 ± 0.5 |
| deepseek-coder, sem filtro | 68% ± 4 | 85% ± 4 | 76% ± 3 | 32% ± 4 | 17.0 ± 0.8 | 8.0 ± 1.4 | 3.0 ± 0.8 |
| deepseek-coder, filtrado | 74% ± 6 | 42% ± 2 | 53% ± 3 | 26% ± 6 | 8.3 ± 0.5 | 3.0 ± 0.8 | 11.7 ± 0.5 |
| deepseek-coder, híbrido A (Semgrep ou SonarQube com hotspots, ou LLM filtrado) | 76% ± 6 | 68% ± 5 | 72% ± 5 | 24% ± 6 | 13.7 ± 0.9 | 4.3 ± 1.2 | 6.3 ± 0.9 |
| deepseek-coder, híbrido B (Semgrep ou SonarQube só vulnerabilities, ou LLM filtrado) | 81% ± 5 | 63% ± 5 | 71% ± 5 | 19% ± 5 | 12.7 ± 0.9 | 3.0 ± 0.8 | 7.3 ± 0.9 |
- deepseek-coder: reprovadas pelo F1: [15, 12, 14]; pelo F2: [0, 0, 1]
| codellama, sem filtro | 69% ± 4 | 93% ± 2 | 79% ± 3 | 31% ± 4 | 17.3 ± 0.5 | 8.0 ± 1.6 | 1.3 ± 0.5 |
| codellama, filtrado | 70% ± 2 | 70% ± 7 | 70% ± 5 | 30% ± 2 | 13.0 ± 0.8 | 5.7 ± 0.5 | 5.7 ± 1.7 |
| codellama, híbrido A (Semgrep ou SonarQube com hotspots, ou LLM filtrado) | 69% ± 1 | 81% ± 11 | 74% ± 5 | 31% ± 1 | 15.0 ± 1.4 | 6.7 ± 0.5 | 3.7 ± 2.4 |
| codellama, híbrido B (Semgrep ou SonarQube só vulnerabilities, ou LLM filtrado) | 72% ± 3 | 81% ± 11 | 76% ± 7 | 28% ± 3 | 15.0 ± 1.4 | 5.7 ± 0.5 | 3.7 ± 2.4 |
- codellama: reprovadas pelo F1: [5, 10, 3]; pelo F2: [0, 1, 2]