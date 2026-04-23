.PHONY: all setup install-deps run

all: install-deps ## Install deps, start server, open browser
	@echo "Starting server on http://localhost:9000"
	@open http://localhost:9000 &
	python app.py

setup: install-deps ## Alias for install-deps

install-deps: ## Install Python dependencies
	pip install -r requirements.txt

run: ## Start server on port 9000
	python app.py
