# Arquitetura do inventário de software

## Fluxo de dados

1. `scanner.py` descobre hosts com Nmap, mantendo a descoberta sem portas como
   padrão.
2. Com `INFRA_SCAN_SERVICES=true`, o scanner executa detecção de versão limitada
   aos 100 ports TCP/UDP mais comuns (`-sV --version-all --top-ports 100`).
3. `core/fingerprint/nmap_parser.py` converte os resultados em serviços
   normalizados. O `core/fingerprint/cpe_mapper.py` gera CPE 2.3 apenas para
   produtos conhecidos e versões válidas; caso contrário, preserva o CPE emitido
   pelo Nmap ou deixa o campo vazio.
4. `core/persistence.py` persiste ativos lógicos, endpoints, instâncias de
   software, evidências, e findings CVE no SQLite.
5. Com `INFRA_CVE_LOOKUP=true`, `core/cve_client.py` consulta a API CVE 2.0 do
   NVD por CPE. As falhas HTTP são exibidas e o scan permanece gravável sem as
   CVEs; erros de formato e de dados não são ocultados.
6. O dashboard exibe o inventário ativo e acrescenta o fator de vulnerabilidade
   ao score.
7. Com a detecção de serviços habilitada, `core/exporter.py` também gera um CSV
   por serviço, produto, versão, endpoint, CPE e CVEs.

## Entidades SQLite

- `assets`: identidade de longo prazo, preferencialmente MAC; hostname/IP são
  alternativas com menor estabilidade.
- `endpoints`: observações efêmeras de IP/porta/protocolo; são desativados se o
  software no mesmo endpoint mudar ou se o ativo reaparecer com outro IP.
- `software_instances`: produto/versão/CPE ligados ao ativo e endpoint, com
  primeira e última observação.
- `evidence`: representação bruta dos metadados de serviço do Nmap, ligada ao
  endpoint e, quando identificado, à instância de software.
- `cve_findings`: vulnerabilidades retornadas pelo NVD para a instância.

Os dados antigos em `scans` e `dispositivos` permanecem no banco. As novas
tabelas são criadas com `CREATE TABLE IF NOT EXISTS`; nenhuma varredura antiga é
convertida retroativamente em software identificado.

`examples/synthetic-scan.json` é uma amostra fictícia usando o endereço de
documentação `192.0.2.0/24`; ela não representa tráfego nem ativos reais.

## Limites atuais

O projeto não implementa ainda coletores p0f, WhatWeb ou JA3/JA3S. A API NVD é
consultada sob demanda durante scans habilitados, sem cache persistente de
respostas. A identificação de versão depende da resposta do serviço e não
confirma que uma CVE seja aplicável ou explorável naquela instalação.