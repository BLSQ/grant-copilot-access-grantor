.PHONY: setup install-op install-deps run

setup: install-op install-deps ## Install all prerequisites

install-op: ## Install 1Password CLI
	brew install --cask 1password-cli

install-deps: ## Install Python dependencies
	pip install -r requirements.txt

run: ## Start server on port 9000
	python app.py
