.PHONY: help install dev test test-cov clean run-scanner run-dashboard run-telegram all backup restore migrate

BLUE := \033[0;34m
GREEN := \033[0;32m
RED := \033[0;31m
NC := \033[0m

help:
	@echo "${BLUE}InfraInsight - Comandos Disponíveis${NC}"
	@echo ""
	@echo "  ${GREEN}make install${NC}      - Instalar dependências"
	@echo "  ${GREEN}make dev${NC}          - Executar em modo desenvolvimento"
	@echo "  ${GREEN}make test${NC}         - Executar testes"
	@echo "  ${GREEN}make test-cov${NC}     - Executar testes com cobertura"
	@echo "  ${GREEN}make clean${NC}        - Limpar arquivos temporários"
	@echo "  ${GREEN}make run-scanner${NC}  - Executar scanner"
	@echo "  ${GREEN}make run-dashboard${NC}- Executar dashboard"
	@echo "  ${GREEN}make run-telegram${NC} - Executar Telegram Bot"
	@echo "  ${GREEN}make all${NC}          - Iniciar todos os serviços"
	@echo "  ${GREEN}make backup${NC}       - Fazer backup"
	@echo "  ${GREEN}make migrate${NC}      - Migrar banco de dados"

install:
	@echo "${BLUE}📦 Instalando dependências...${NC}"
	pip install -r requirements.txt
	@echo "${GREEN}✅ Instalação concluída!${NC}"

dev:
	@echo "${BLUE}🚀 Modo desenvolvimento...${NC}"
	export FLASK_ENV=development
	export FLASK_APP=dashboard/app.py
	flask run --host=0.0.0.0 --port=5000

test:
	@echo "${BLUE}🧪 Executando testes...${NC}"
	pytest tests/ -v --tb=short

test-cov:
	@echo "${BLUE}🧪 Executando testes com cobertura...${NC}"
	pytest tests/ -v --cov=core --cov=dashboard --cov-report=html --cov-report=term
	@echo "${GREEN}✅ Relatório em htmlcov/index.html${NC}"

clean:
	@echo "${BLUE}🧹 Limpando...${NC}"
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache .coverage htmlcov .mypy_cache
	@echo "${GREEN}✅ Limpeza concluída!${NC}"

run-scanner:
	@echo "${BLUE}🔍 Iniciando scanner...${NC}"
	python scanner.py

run-dashboard:
	@echo "${BLUE}📊 Iniciando dashboard...${NC}"
	python dashboard/app.py

run-telegram:
	@echo "${BLUE}🤖 Iniciando Telegram Bot...${NC}"
	python core/telegram_bot.py

all:
	@echo "${BLUE}🚀 Iniciando todos os serviços...${NC}"
	./start_all.sh

backup:
	@echo "${BLUE}💾 Fazendo backup...${NC}"
	./scripts/backup.sh

migrate:
	@echo "${BLUE}🗄️ Migrando banco de dados...${NC}"
	python scripts/migrate_db.py
