@echo off
title COPA AI Access Grantor

echo.
echo  ========================================
echo   COPA AI Access Grantor
echo  ========================================
echo.

:: Check Docker is available
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Docker is not installed or not running.
    echo.
    echo  Please install Docker Desktop from:
    echo  https://www.docker.com/products/docker-desktop/
    echo.
    echo  After installing, make sure Docker Desktop is running,
    echo  then double-click this file again.
    echo.
    pause
    exit /b 1
)

:: Check .env exists
if not exist ".env" (
    echo  [ERROR] .env file not found.
    echo.
    echo  Please copy .env.example to .env and fill in your credentials:
    echo    copy .env.example .env
    echo.
    echo  Then double-click this file again.
    echo.
    pause
    exit /b 1
)

:: Build image
echo  Building Docker image...
docker build -t copa-ai-access-grantor . >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Docker build failed. See output above.
    pause
    exit /b 1
)

echo  Starting server on http://localhost:9999
echo.
echo  Opening browser...
start http://localhost:9999

echo  Press Ctrl+C to stop the server.
echo.

:: Run container
docker run --rm -p 9999:9999 --env-file .env copa-ai-access-grantor

pause
