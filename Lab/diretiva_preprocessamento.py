import os
import re

# 1. Ajuste este nome caso a sua pasta manual tenha outro nome
DIR_SAST = "dataset_sast" 
DIR_LLM = "dataset_llm"

def sanitizar_codigo(codigo_fonte: str) -> str:
    """Remove comentários, licenças, marcadores e linhas vazias excessivas."""
    # Remove marcadores de desafio do OWASP Juice Shop
    codigo = re.sub(r'//\s*vuln-code-snippet.*', '', codigo_fonte)
    # Remove comentários multilinha /* ... */
    codigo = re.sub(r'/\*[\s\S]*?\*/', '', codigo)
    # Remove comentários de linha única // ...
    codigo = re.sub(r'//.*', '', codigo)
    
    # Normaliza linhas vazias
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

    # Busca recursiva por arquivos .ts e .js (incluindo subpastas)
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
        
        # Garante que as subpastas de destino existam
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