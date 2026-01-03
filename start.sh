#!/bin/bash
# Network Sentinel - Quick Start Script
# Run this to start the application locally (without Docker)

set -e

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

echo "=========================================="
echo "  Network Sentinel - Starting Services"
echo "=========================================="

# Check if Ollama is running
if ! curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "[!] Ollama is not running. Please start it first:"
    echo "    systemctl start ollama"
    exit 1
fi
echo "[OK] Ollama is running"

# Activate virtual environment
source venv/bin/activate

# Start backend in background
echo "[*] Starting FastAPI backend on port 8000..."
cd backend
uvicorn main:app --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!
cd ..

sleep 2

# Start frontend
echo "[*] Starting Next.js frontend on port 3000..."
cd frontend
npm run dev &
FRONTEND_PID=$!
cd ..

echo ""
echo "=========================================="
echo "  Services Started!"
echo "=========================================="
echo ""
echo "  Frontend:  http://localhost:3000"
echo "  Backend:   http://localhost:8000"
echo "  API Docs:  http://localhost:8000/docs"
echo ""
echo "  Press Ctrl+C to stop all services"
echo ""

# Handle cleanup on exit
cleanup() {
    echo ""
    echo "[*] Stopping services..."
    kill $BACKEND_PID 2>/dev/null || true
    kill $FRONTEND_PID 2>/dev/null || true
    echo "[OK] Services stopped"
}

trap cleanup EXIT INT TERM

# Wait for processes
wait
