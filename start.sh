#!/usr/bin/env bash
set -e

echo ""
echo "  ========================================"
echo "   COPA AI Access Grantor"
echo "  ========================================"
echo ""

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "  [ERROR] Docker is not installed or not running."
    echo ""
    echo "  Install Docker Desktop: https://www.docker.com/products/docker-desktop/"
    exit 1
fi

# Check .env
if [ ! -f .env ]; then
    echo "  [ERROR] .env file not found."
    echo ""
    echo "  Run: cp .env.example .env"
    echo "  Then fill in your credentials and run this script again."
    exit 1
fi

echo "  Building Docker image..."
docker build -t copa-ai-access-grantor . > /dev/null 2>&1

echo "  Starting server on http://localhost:9999"
echo ""

# Open browser (macOS or Linux)
if command -v open &> /dev/null; then
    open http://localhost:9999 &
elif command -v xdg-open &> /dev/null; then
    xdg-open http://localhost:9999 &
fi

echo "  Press Ctrl+C to stop the server."
echo ""

docker run --rm -p 9999:9999 --env-file .env copa-ai-access-grantor
