import os
import re

# 1. Ajuste este nome caso a sua pasta manual tenha outro nome
DIR_SAST = "dataset_sast" 
DIR_LLM = "dataset_llm"

_CHARS_ANTES_DE_REGEX = set("(,=:[!&|?{};+-*%<>~^")


def _pode_iniciar_regex(saida: list) -> bool:
    """Decide se um '/' na posição atual abre um literal de regex (e não uma divisão)."""
    texto = "".join(saida).rstrip()
    if not texto:
        return True
    if texto[-1] in _CHARS_ANTES_DE_REGEX:
        return True
    return bool(re.search(r'\b(return|typeof|case|in|of|delete|void|throw)$', texto))


def remover_comentarios(codigo: str) -> str:
    """Remove comentários // e /* */ respeitando strings, templates e regex (o regex `//.*` truncava URLs)."""
    saida = []
    i, n = 0, len(codigo)
    pilha_tpl = []  # profundidade de chaves abertas em cada ${ } de template ativo

    def copiar_string(aspa):
        nonlocal i
        saida.append(codigo[i]); i += 1
        while i < n:
            c = codigo[i]
            saida.append(c); i += 1
            if c == "\\" and i < n:
                saida.append(codigo[i]); i += 1
            elif c == aspa or (c == "\n" and aspa != "`"):
                return

    def copiar_template():
        """Copia o trecho literal de um template até fechar a crase ou abrir ${."""
        nonlocal i
        while i < n:
            c = codigo[i]
            if c == "\\" and i + 1 < n:
                saida.append(codigo[i:i + 2]); i += 2
            elif c == "`":
                saida.append(c); i += 1
                return False  # template terminou
            elif c == "$" and i + 1 < n and codigo[i + 1] == "{":
                saida.append("${"); i += 2
                pilha_tpl.append(0)
                return True   # entrou em expressão ${ }
            else:
                saida.append(c); i += 1
        return False

    while i < n:
        c = codigo[i]
        prox = codigo[i + 1] if i + 1 < n else ""
        if c in "'\"":
            copiar_string(c)
        elif c == "`":
            saida.append(c); i += 1
            copiar_template()
        elif pilha_tpl and c == "{":
            pilha_tpl[-1] += 1; saida.append(c); i += 1
        elif pilha_tpl and c == "}":
            if pilha_tpl[-1] == 0:
                pilha_tpl.pop(); saida.append(c); i += 1
                copiar_template()  # volta ao trecho literal do template
            else:
                pilha_tpl[-1] -= 1; saida.append(c); i += 1
        elif c == "/" and prox == "/":
            while i < n and codigo[i] != "\n":
                i += 1
        elif c == "/" and prox == "*":
            fim = codigo.find("*/", i + 2)
            i = n if fim == -1 else fim + 2
        elif c == "/" and _pode_iniciar_regex(saida):
            saida.append(c); i += 1
            em_classe = False
            while i < n:
                d = codigo[i]
                saida.append(d); i += 1
                if d == "\\" and i < n:
                    saida.append(codigo[i]); i += 1
                elif d == "[":
                    em_classe = True
                elif d == "]":
                    em_classe = False
                elif d == "/" and not em_classe:
                    break
                elif d == "\n":
                    break
        else:
            saida.append(c); i += 1
    return "".join(saida)


def sanitizar_codigo(codigo_fonte: str) -> str:
    """Remove comentários, marcadores do Juice Shop e linhas vazias excessivas."""
    codigo = remover_comentarios(codigo_fonte)

    linhas = [linha.rstrip() for linha in codigo.splitlines()]
    linhas_limpas = []
    anterior_vazia = False
    
    for linha in linhas:
        if not linha:
            if not anterior_vazia:
                linhas_limpas.append("")
                anterior_vazia = True
        else:
            linhas_limpas.append(linha)
            anterior_vazia = False
            
    return "\n".join(linhas_limpas).strip()

def executar_pipeline_preprocessing():
    if not os.path.exists(DIR_SAST):
        print(f"[!] ERRO: A pasta '{DIR_SAST}' não foi encontrada no diretório atual.")
        print(f"    Caminho atual: {os.getcwd()}")
        print("    Ação: Crie a pasta 'dataset_sast' e coloque seus arquivos nela, ou altere a variável DIR_SAST no script.")
        return

    arquivos_encontrados = []
    for root, _, files in os.walk(DIR_SAST):
        for f in files:
            if f.lower().endswith(('.ts', '.js')):
                caminho_completo = os.path.join(root, f)
                rel_path = os.path.relpath(caminho_completo, DIR_SAST)
                arquivos_encontrados.append((caminho_completo, rel_path))

    if not arquivos_encontrados:
        print(f"[!] ERRO: Nenhum arquivo .ts ou .js foi encontrado dentro de '{DIR_SAST}'.")
        print("    Verifique se os arquivos estão gravados com a extensão correta (.ts ou .js).")
        return

    os.makedirs(DIR_LLM, exist_ok=True)
    print(f"[*] Iniciando pré-processamento de {len(arquivos_encontrados)} arquivos do dataset manual...")

    total_linhas_originais = 0
    total_linhas_sanitizadas = 0

    for idx, (caminho_orig, rel_path) in enumerate(sorted(arquivos_encontrados), 1):
        caminho_dest = os.path.join(DIR_LLM, rel_path)
        
        os.makedirs(os.path.dirname(caminho_dest), exist_ok=True)

        with open(caminho_orig, 'r', encoding='utf-8', errors='ignore') as f:
            conteudo_orig = f.read()

        conteudo_limpo = sanitizar_codigo(conteudo_orig)

        with open(caminho_dest, 'w', encoding='utf-8') as f:
            f.write(conteudo_limpo)

        l_orig = len(conteudo_orig.splitlines())
        l_limp = len(conteudo_limpo.splitlines())
        
        total_linhas_originais += l_orig
        total_linhas_sanitizadas += l_limp

        print(f"[{idx:02d}/{len(arquivos_encontrados)}] {rel_path}: {l_orig} -> {l_limp} linhas")

    if total_linhas_originais > 0:
        reducao = ((total_linhas_originais - total_linhas_sanitizadas) / total_linhas_originais) * 100
        print("\n[✔] Pré-processamento concluído com sucesso!")
        print(f"    - Linhas totais originais: {total_linhas_originais}")
        print(f"    - Linhas totais sanitizadas: {total_linhas_sanitizadas}")
        print(f"    - Redução média de ruído: {reducao:.2f}%")

if __name__ == "__main__":
    executar_pipeline_preprocessing()