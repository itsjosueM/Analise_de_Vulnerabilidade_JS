---
ID: 1-202609121149
tags:
  - "#nota-referencia"
  - "#SistemasdeInformação"
Tema: 1 - SRC
---
# Referencias
# Relevância
# Notas Relacionadas
# Resumo
Estudo comparativo entre ferramentas SAST (Semgrep/SonarQube) e modelos LLM (DeepSeek/CodeLlama) na detecção de vulnerabilidades em JavaScript (OWASP Juice Shop). Resultados revelam complementaridade: SASTs alcançam 100% de precisão para vulnerabilidades padrão (XSS/SQLi), enquanto LLMs oferecem maior recall (70% no DeepSeek) para ameaças contextuais (NoSQLi/Broken Access Control). A taxa de 22-45% de falsos positivos em LLMs demanda estratégias de filtragem. Demonstramos que pipelines híbridos combinam de forma ideal a precisão SAST com cobertura LLM. O estudo contribui com evidências empíricas para a adoção de LLMs em pipelines de segurança, destacando desafios como a mitigação de falsos positivos.
# Citações e Comentários
## Contexto 
A linguagem de programação mais utilizada para desenvolvimento web (JavaScript), possui certas caracteristicas que viabilizam ataques e, para a mitigação ou redução desses ataques, é necessário utilizar estratégias que possam metrificar a vulnerabilidade do código fonte. O trabalho propõe a análise de dois métodos: SASTs (Static Application Security Testing) e a análise do código fonte com inteligências artificiais generativas.

O trabalho utiliza uma aplicação web utilizada para treino em segurança da informação chamada OWASP Juice Shop.

## Problemática
*Embora tradicionais, os SASTs enfrentam dificuldades em detecção de vulnerabilidades contextuais, de lógica de negócio e altas taxas de falsos-positivos.*

Large Language Models (LLMs) como o gpt-4, codeLLAMA e DeepSeek têm se mostrado eficazes na análise de vulnerabilidade em código python, C e Java, reduzindo as limitações do método tradicional de SAST, no entanto, ainda há uma lacuna na literatura em relação a JavaScript, linguagem que impõe desafios a analise automatizada

## Objetivos
- **Objetivo geral:** investigar se os LLMs superam SASTs apresentando maior eficácia na detecção de vulnerabilidades e contribuam para a redução de falsos positivos em JavaScript. Além disso, este estudo visa orientar desenvolvedores na escolha de ferramentas adequadas e apoiar pesquisas futuras sobre a aplicação de LLMs em segurança web. Dessa forma, esta pesquisa se propõe a preencher uma lacuna crítica na segurança de aplicações web, investigando o papel emergente dos LLMs no cenário JavaScript. Ao investigar o papel emergente dos LLMs na segurança de aplicações JavaScript, este estudo pode contribuir não apenas para o avanço acadêmico, mas também para a adoção segura de IA no desenvolvimento web moderno.

- **Objetivos específicos:** (1) Extrair e estruturar uma coleção de vulnerabilidades a partir do OWASP Juice Shop, formando um dataset representativo paraavaliação comparativa das ferramentas; (2) Avaliar precisão, recall e F1-score das ferramentas; (3) Avaliar o impacto operacional das ferramentas.

## Metodologia
Estudo de abordagem quantitativa em prol de se abordar o desempenho de ferramentas SAST e LLMs na detecção de vulnerabilidades em JavaScript.

	(1) Construção de um dataset validado
	(2) Pré-processamento do código-fonte
	(3) Configruação das ferramentas
	(4) Execução automatizada com métricas precisas

**1:** Os autores utilizaram um subconjunto de 15 arquivos baseados na aplicação web OWASP Juice Shop (Versã0 17.3.0), contendo 10 arquivos vulneráveis e 5 arquivos corrigidos e seguros. Os arquivos seguros foram idetificados pelo sufixo correct.ts.

**2:** Um pré-processamento do código foi aplicado em prol de se remover ruídos que poderiam influenciar na análise via LLMs (comentarios, blocos de código multi-linha, marcadores de desafio e outros)

**3:** Duas abordagens de análise estática foram selecionadas (SAST e análise via LLMs).
- Ferramentas SAST: SonarQube Community Build, Semgrep.
- LLMs: DeepSeek-Coder (via Ollama), CodeLlama (via Ollama) com prompts estruturados para análise de vulnerabilidades 
- *Prompt utilizado: "Analise os riscos de segurança no código abaixo , seguindo o
OWASP Top 10. Retorne APENAS se houver vulnerabilidades , no
formato JSON abaixo . Caso contrário , retorne "Código seguro ".
{
" Arquivo ": " Nome do arquivo ",
" Trecho Vulner ável ": "O snippet de código específico que contém a vulnerabilidade". 
" Tipo da Vulnerabilidade ": "A categoria da vulnerabilidade ",
" Descri ção Breve ": "Uma explicação concisa (1 -2 frases ) de
por que esse trecho é vulnerável "
}"
**4:** Dividida em três etapas principais (varredura inicial em busca de possiveis vulnerabilidades, classificação dos alertas de possiveis vulnerabilidades em: verdadeiros positivos - vulnerabilidades corretamente detectadas, falsos positivos - alertas incorretos, e falsos negativos, que indicam vulnerabilidades existentes que não foram detectadas.)







