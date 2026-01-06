.PHONY: help install install-dev lint format type-check test test-cov clean build pre-commit-install

# Default target
help:
	@echo "OWASP Agentic AI Scanner - Development Commands"
	@echo ""
	@echo "Setup:"
	@echo "  install        Install production dependencies"
	@echo "  install-dev    Install development dependencies"
	@echo ""
	@echo "Quality:"
	@echo "  lint              Run ruff linter"
	@echo "  format            Format code with ruff"
	@echo "  type-check        Run mypy type checking"
	@echo "  pre-commit        Run all checks (lint, type-check, test)"
	@echo "  pre-commit-install Install pre-commit git hooks"
	@echo ""
	@echo "Testing:"
	@echo "  test           Run tests"
	@echo "  test-cov       Run tests with coverage"
	@echo ""
	@echo "Build:"
	@echo "  build          Build distribution packages"
	@echo "  clean          Remove build artifacts"
	@echo ""
	@echo "Usage:"
	@echo "  scan           Run scanner on example path"

# Setup
install:
	uv sync

install-dev:
	uv sync --all-extras
	uv run pre-commit install

pre-commit-install:
	uv run pre-commit install

# Quality
lint:
	uv run ruff check src tests

format:
	uv run ruff format src tests
	uv run ruff check --fix src tests

type-check:
	uv run mypy src

pre-commit: format lint type-check test
	@echo "All checks passed!"

# Testing
test:
	uv run pytest tests/

test-cov:
	uv run pytest tests/ --cov=src/owasp_agentic_scanner --cov-report=term-missing --cov-report=html

# Build
build:
	uv build

clean:
	rm -rf dist/ build/ .eggs/ *.egg-info/
	rm -rf .pytest_cache/ .mypy_cache/ .ruff_cache/
	rm -rf htmlcov/ .coverage coverage.xml
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

# Usage example
scan:
	uv run owasp-scan scan . --rules goal_hijack,code_execution

