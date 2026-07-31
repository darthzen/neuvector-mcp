.DEFAULT_GOAL := help
PY      ?= python3
IMAGE   ?= neuvector-mcp
TAG     ?= 1.0.3
REGISTRY?= localhost:5000

.PHONY: help
help: ## show targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n",$$1,$$2}'

.PHONY: install
install: ## install the package plus dev extras into the active environment
	$(PY) -m pip install -e '.[dev]'

.PHONY: lint
lint: ## ruff check + format check
	$(PY) -m ruff check src tests scripts
	$(PY) -m ruff format --check src tests scripts

.PHONY: fmt
fmt: ## apply ruff formatting
	$(PY) -m ruff check --fix src tests scripts
	$(PY) -m ruff format src tests scripts

.PHONY: types
types: ## strict mypy
	$(PY) -m mypy

.PHONY: test
test: ## unit + contract tests with coverage gate
	$(PY) -m pytest --cov --cov-report=term-missing

.PHONY: spec
spec: ## machine-checkable spec compliance gate
	$(PY) scripts/verify_spec.py

.PHONY: smoke
smoke: ## start over stdio against a live controller and list tools
	$(PY) scripts/smoke_stdio.py

.PHONY: verify
verify: lint types test spec ## the full gate; CI runs exactly this
	@echo "VERIFY OK"

.PHONY: image
image: ## build the container image on SUSE BCI
	podman build -t $(REGISTRY)/$(IMAGE):$(TAG) -f deploy/Dockerfile .

.PHONY: clean
clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov dist build
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
