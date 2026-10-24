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
8. Scans completos podem registrar transições de presença no SQLite. A identidade
   usa MAC quando disponível e IP como alternativa; uma saída só é confirmada
   depois de dois scans completos consecutivos sem o dispositivo.
9. Com `INFRA_SCAN_SNMP=true`, consultas SNMPv2c somente leitura enriquecem os
   hosts já descobertos. A comunidade é fornecida por configuração local e não é
   persistida no banco nem nos relatórios.

## Histórico de presença

`device_presence` mantém o estado por rede, `device_presence_networks` marca o
baseline inicial e `device_events` armazena eventos `ENTROU`/`SAIU`. O primeiro
scan completo de cada rede apenas inicializa o baseline. Scans vazios também são
salvos para que possam contar como ausência; snapshots não marcados como
completos não alteram esse estado.

Eventos cujo MAC tem o bit U/L definido são marcados como `mac_randomizado` e
apresentados como possível randomização no dashboard e no Telegram. O bit indica
um endereço localmente administrado, não prova que o endereço foi gerado por
randomização de privacidade. Esses eventos continuam no histórico e podem
produzir entrada/saída por MAC, portanto a flag deve ser considerada antes de
futuras notificações de "novo dispositivo". Durante a migração, eventos
existentes também recebem a flag calculada a partir do MAC salvo.

O horário de `device_events` é o horário em que o scan confirmou/detectou a
transição, não a hora exata em que o dispositivo conectou ou desconectou. Scans
ativos só delimitam quando a mudança ocorreu; para precisão em tempo real é
necessário integrar uma fonte passiva, como syslog do roteador.

O timestamp é gravado pelo scanner como horário local sem informação de fuso.
Dashboard e Telegram exibem esse mesmo horário sem conversão. A timeline mostra
os dez eventos mais recentes e a API autenticada `GET /api/eventos` aceita
`limite` de 1 a 200 e um filtro opcional `rede` (a chave de rede registrada).
O bot Telegram oferece o comando `/eventos` para as dez movimentações mais
recentes.

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
- `device_presence` e `device_events`: estado e transições de presença de
  dispositivos observados por scans completos.

Os dados antigos em `scans` e `dispositivos` permanecem no banco. As novas
tabelas são criadas com `CREATE TABLE IF NOT EXISTS`; nenhuma varredura antiga é
convertida retroativamente em software identificado.

`examples/synthetic-scan.json` é uma amostra fictícia usando o endereço de
documentação `192.0.2.0/24`; ela não representa tráfego nem ativos reais.

## Limites atuais

O projeto não implementa ainda coletores p0f, WhatWeb ou JA3/JA3S. A precisão do
classificador, a cobertura SNMP e a estabilidade do histórico de presença ainda
não foram avaliadas empiricamente em amostras representativas. A identificação
de versão depende da resposta do serviço e não confirma que uma CVE seja
aplicável ou explorável naquela instalação.