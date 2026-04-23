.PHONY: all setup install-deps run docker docker-build docker-run

all: install-deps ## Install deps, start server, open browser
	@echo "Starting server on http://localhost:9999"
	@open http://localhost:9999 &
	python app.py

setup: install-deps ## Alias for install-deps

install-deps: ## Install Python dependencies
	pip install -r requirements.txt

run: ## Start server on port 9999
	python app.py

docker: docker-build docker-run ## Build and run via Docker

docker-build: ## Build Docker image
	docker build -t copa-ai-access-grantor .

docker-run: ## Run Docker container (uses .env file or env vars)
	@echo "Starting server on http://localhost:9999"
	@open http://localhost:9999 &
	@if [ -f .env ]; then \
		docker run --rm -p 9999:9999 --env-file .env copa-ai-access-grantor; \
	else \
		docker run --rm -p 9999:9999 \
			-e AUTH0_DOMAIN \
			-e AUTH0_CLIENT_ID \
			-e AUTH0_CLIENT_SECRET \
			-e OP_SERVICE_ACCOUNT_TOKEN \
			-e OP_VAULT_ID \
			-e RESEND_API_KEY \
			-e RESEND_FROM \
			copa-ai-access-grantor; \
	fi
