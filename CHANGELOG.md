# Changelog

## [Unreleased]

### Changed
- **BREAKING:** InfraScore now uses `min(10, ((R + S) / 7) * 10)`. The base
  exposure component `R` has a maximum of 7, and the CVE component `S` has a
  maximum of 3. Scores calculated by earlier releases using direct sums of
  port weights may differ even when no CVEs are present; historical scores
  should not be compared without accounting for this formula change.

## [1.0.0] - 2026-08-31

### Added
- Scanner ARP para descoberta de dispositivos
- Classificação automática de dispositivos
- InfraScore - métrica heurística de exposição
- Dashboard web com Flask e tema escuro
- Histórico de varreduras em SQLite
- Alertas automáticos para serviços expostos
- Relatórios em PDF e CSV
- Integração com Telegram Bot
- Sistema de testes automatizados (pytest)
- CI/CD Pipeline com GitHub Actions
- Scripts de backup e deploy
- Makefile para comandos comuns
- Documentação completa

### Security
- Autenticação no dashboard
- Proteção contra CSRF
- Variáveis de ambiente para configuração
