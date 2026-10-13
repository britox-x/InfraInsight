# Portas de detecção de serviços

Com `INFRA_SCAN_SERVICES=true`, o scanner usa Nmap `-sV --version-all` nas
100 portas TCP abaixo, ordenadas pela frequência do banco `nmap-services` da
versão Nmap 7.94SVN. A lista pode variar em prioridade entre versões futuras do
Nmap; aqui ela está fixada no projeto para scans reproduzíveis e não depende do
banco Nmap instalado na máquina de execução ou no CI.

Para substituir totalmente a seleção padrão, configure uma lista de portas
separadas por vírgula:

```bash
INFRA_SCAN_PORTS=22,80,443,8443 python scanner.py
```

Cada porta deve ser um inteiro entre 1 e 65535, sem duplicatas. Variável ausente
ou vazia usa a lista completa abaixo.

| Ordem | TCP | Ordem | TCP | Ordem | TCP | Ordem | TCP |
|------:|----:|------:|----:|------:|----:|------:|----:|
| 1 | 80 | 26 | 465 | 51 | 5000 | 76 | 8009 |
| 2 | 23 | 27 | 548 | 52 | 5631 | 77 | 3128 |
| 3 | 443 | 28 | 113 | 53 | 631 | 78 | 444 |
| 4 | 21 | 29 | 81 | 54 | 49153 | 79 | 9999 |
| 5 | 22 | 30 | 6001 | 55 | 8081 | 80 | 5009 |
| 6 | 25 | 31 | 10000 | 56 | 2049 | 81 | 7070 |
| 7 | 3389 | 32 | 514 | 57 | 88 | 82 | 5190 |
| 8 | 110 | 33 | 5060 | 58 | 79 | 83 | 3000 |
| 9 | 445 | 34 | 179 | 59 | 5800 | 84 | 5432 |
| 10 | 139 | 35 | 1026 | 60 | 106 | 85 | 3986 |
| 11 | 143 | 36 | 2000 | 61 | 2121 | 86 | 1900 |
| 12 | 53 | 37 | 8443 | 62 | 1110 | 87 | 13 |
| 13 | 135 | 38 | 8000 | 63 | 49155 | 88 | 1029 |
| 14 | 3306 | 39 | 32768 | 64 | 6000 | 89 | 9 |
| 15 | 8080 | 40 | 554 | 65 | 513 | 90 | 6646 |
| 16 | 1723 | 41 | 26 | 66 | 990 | 91 | 5051 |
| 17 | 111 | 42 | 1433 | 67 | 5357 | 92 | 49157 |
| 18 | 995 | 43 | 49152 | 68 | 427 | 93 | 1028 |
| 19 | 993 | 44 | 2001 | 69 | 49156 | 94 | 873 |
| 20 | 5900 | 45 | 515 | 70 | 543 | 95 | 1755 |
| 21 | 1025 | 46 | 8008 | 71 | 544 | 96 | 2717 |
| 22 | 587 | 47 | 49154 | 72 | 5101 | 97 | 4899 |
| 23 | 8888 | 48 | 1027 | 73 | 144 | 98 | 9100 |
| 24 | 199 | 49 | 5666 | 74 | 7 | 99 | 119 |
| 25 | 1720 | 50 | 646 | 75 | 389 | 100 | 37 |
