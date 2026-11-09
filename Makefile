VENV := .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
SKILLS_DIR ?=

.PHONY: install semgrep mcp run mcp-run install-skill agent-setup test format docker-up docker-down docker-status docker-logs service-install service-status service-logs service-restart service-uninstall

install:
	python3 -m venv $(VENV)
	$(PIP) install -r requirements-dev.txt

semgrep:
	$(PIP) install -r requirements-semgrep.txt

mcp:
	$(PIP) install -r requirements-mcp.txt

run:
	$(VENV)/bin/uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# 以 stdio 執行 MCP server（通常由 Agent 客戶端啟動，不需要手動跑）
mcp-run:
	$(PY) -m sast_mcp.server

# 跨平台安裝：Docker 啟動服務 + 安裝 skill + 印出 MCP 註冊指令
agent-setup:
	$(PY) scripts/agent_setup.py

# 把 triage skill 安裝到 OpenCode 全域 skills 目錄（可用 SKILLS_DIR 覆寫）
install-skill:
	$(PY) scripts/install_skill.py $(if $(SKILLS_DIR),--skills-dir "$(SKILLS_DIR)",)

test:
	$(VENV)/bin/pytest -q

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down

docker-status:
	docker compose ps

docker-logs:
	docker compose logs -f

# systemd user service（替代方案，不要與 Docker 同時使用）
service-install:
	./scripts/install-service.sh

service-status:
	systemctl --user --no-pager status sast.service

service-logs:
	journalctl --user -u sast.service -f

service-restart:
	systemctl --user restart sast.service

service-uninstall:
	./scripts/uninstall-service.sh
