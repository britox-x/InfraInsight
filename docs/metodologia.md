# Metodologia de identificação e risco

## Identificação do software

O Nmap fornece protocolo, porta, estado, nome do serviço, produto, versão,
confiança e, quando disponível, CPE. O parser considera somente portas abertas.
Confiança Nmap de 0–10 é convertida para 0–100; valores inválidos ficam sem
confiança. CPEs explícitos são marcados como origem `nmap`; o mapeador local
marca CPEs inferidos como `inferred`.

## Correlação CVE

O NVD é consultado apenas quando `INFRA_CVE_LOOKUP=true`. Um CPE explicitamente
retornado pelo Nmap pode ser consultado independentemente da confiança. CPEs
inferidos precisam atingir `INFRA_CVE_MIN_CONFIDENCE` (padrão 70). Se o limiar
não for alcançado, o serviço é salvo com `cve_status=skipped_low_confidence`;
falhas sem cache resultam em `unavailable`, sem interromper o scan.

Respostas são armazenadas na tabela SQLite `cve_cache`, indexada pelo CPE. O TTL
padrão é 48 horas (`INFRA_CVE_CACHE_TTL_HOURS`). Quando o NVD falha e há uma
resposta em cache, mesmo expirada, ela é reutilizada e um aviso é enviado ao log.
`INFRA_NVD_API_KEY` é opcional e deve ser fornecida pelo ambiente, nunca
armazenada no repositório. O cliente lê CVSS v4.0, v3.1, v3.0 ou v2, nessa ordem.

## InfraScore

O score calcula os fatores binários `T` (Telnet), `Q` (RTSP), `U` (mais de 30%
de hosts desconhecidos), `H` (HTTP/HTTPS no gateway) e `A` (porta administrativa
aberta). A parcela base é `R = 2T + 2Q + U + H + A`, com máximo 7.

A parcela de software é `S = min(3, 3*Ccrit + 2*Calta + Cmed)`, onde `Ccrit`,
`Calta` e `Cmed` são contagens de CVEs críticas, altas e médias, respectivamente,
deduplicadas por instância/CVE. A pontuação final é:

```text
InfraScore = min(10.0, ((R + S) / 7.0) * 10)
```

Sem CVEs, o score usa a fórmula base normalizada e permanece entre 0 e 10. A
pontuação é um indicador heurístico de exposição, não uma probabilidade de
comprometimento nem confirmação de explorabilidade. Esta normalização altera a
escala numérica da implementação anterior do repositório (que somava +3 para
Telnet e +1 para RTSP sem divisor); comparar históricos anteriores exige
considerar essa mudança de fórmula.

## Identidade e histórico

O ativo é reconciliado por MAC normalizado. Quando não há MAC, usa hostname
normalizado e, por último, IP. Essa alternativa pode fundir ou separar ativos
incorretamente; o identificador não deve ser interpretado como identidade física
garantida. IP, porta e protocolo permanecem no endpoint, permitindo consultar
software sem usar o IP como identidade principal.

Scans de versão geram tráfego ativo e devem ser usados apenas em redes e sistemas
sob autorização. O modo padrão continua limitado à descoberta de hosts.
