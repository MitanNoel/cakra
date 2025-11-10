#!/usr/bin/env bash
set -eu

# Unified CAKRA startup script with full setup
# - Installs system deps, Python/npm deps, Ollama + models
# - Starts backend and frontend
# - Uses tmux when available to provide split panes
# - Supports --backend-only, --frontend-only, --skip-install

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"

print() { printf "%b\n" "$1"; }

if [ ! -d "$ROOT_DIR/cakra-system" ] || [ ! -d "$ROOT_DIR/cakra-web" ]; then
    print "❌ Error: please run this script from the project root where 'cakra-system' and 'cakra-web' exist"
    exit 1
fi

BACKEND_CMD="cd $ROOT_DIR/cakra-system && python -m cakra serve --host 0.0.0.0 --port 8000"
FRONTEND_CMD="cd $ROOT_DIR/cakra-web && npm run dev -- --host 0.0.0.0"

MODE="both"
USE_TMUX=true
SKIP_INSTALL=false

while [ $# -gt 0 ]; do
    case "$1" in
        --backend-only) MODE="backend" ; shift ;;
        --frontend-only) MODE="frontend" ; shift ;;
        --no-tmux) USE_TMUX=false ; shift ;;
        --skip-install) SKIP_INSTALL=true ; shift ;;
        -h|--help)
             print "Usage: $0 [--backend-only|--frontend-only] [--no-tmux] [--skip-install]"; exit 0 ;;
        *) print "Unknown arg: $1"; exit 1 ;;
    esac
done

cleanup() {
    print "\n🛑 Shutting down CAKRA system..."
    if [ -n "${BACKEND_PID:-}" ] && kill -0 "$BACKEND_PID" 2>/dev/null; then
        print "Stopping backend (PID: $BACKEND_PID)..."
        kill "$BACKEND_PID" 2>/dev/null || true
    fi
    if [ -n "${FRONTEND_PID:-}" ] && kill -0 "$FRONTEND_PID" 2>/dev/null; then
        print "Stopping frontend (PID: $FRONTEND_PID)..."
        kill "$FRONTEND_PID" 2>/dev/null || true
    fi
    if [ -n "${OLLAMA_PID:-}" ] && kill -0 "$OLLAMA_PID" 2>/dev/null; then
        print "Stopping Ollama (PID: $OLLAMA_PID)..."
        kill "$OLLAMA_PID" 2>/dev/null || true
    fi
    exit 0
}

trap cleanup SIGINT SIGTERM

# Helper to wait for HTTP endpoint
wait_for_http() {
    local url="$1"; local timeout=${2:-20}; local i=0
    while ! curl -sS --max-time 2 "$url" >/dev/null 2>&1; do
        sleep 1; i=$((i+1))
        if [ $i -ge $timeout ]; then return 1; fi
    done
    return 0
}

# Installation steps
if ! $SKIP_INSTALL; then
    print "🔧 Checking and installing dependencies..."

    # System deps (Ubuntu/Debian)
    if command -v apt-get >/dev/null 2>&1; then
        print "📦 Installing system dependencies..."
        sudo apt-get update -qq
        sudo apt-get install -y -qq \
            libatk1.0-0t64 \
            libatk-bridge2.0-0t64 \
            libcups2t64 \
            libxkbcommon0 \
            libatspi2.0-0t64 \
            libxcomposite1 \
            libxdamage1 \
            libxfixes3 \
            libxrandr2 \
            libgbm1 \
            libasound2t64 \
            curl
    fi

    # Ollama setup
    if ! command -v ollama >/dev/null 2>&1; then
        print "🤖 Installing Ollama..."
        curl -fsSL https://ollama.ai/install.sh | sh
    fi

    print "🚀 Starting Ollama service..."
    nohup ollama serve >/dev/null 2>&1 &
    OLLAMA_PID=$!
    sleep 3

    print "📥 Pulling AI models..."
    ollama pull claude-sonnet-4.5 || print "⚠️ Failed to pull claude-sonnet-4.5 (optional)"
    ollama pull llava-phi3 || print "⚠️ Failed to pull llava-phi3 (optional)"
    ollama pull llama2:7b || print "⚠️ Failed to pull llama2:7b (optional)"

    print "✅ Dependencies installed"
fi

if $USE_TMUX && command -v tmux >/dev/null 2>&1 && [ "$MODE" = "both" ]; then
    SESSION="cakra-dev"
    if tmux has-session -t "$SESSION" 2>/dev/null; then
        tmux kill-session -t "$SESSION" >/dev/null 2>&1 || true
    fi
    print "🪟 Launching tmux session '$SESSION' (backend + frontend)..."
    tmux new-session -d -s "$SESSION" "$BACKEND_CMD"
    tmux split-window -v -t "$SESSION" "$FRONTEND_CMD"
    tmux select-layout -t "$SESSION" even-vertical >/dev/null 2>&1 || true
    print "✨ Attach with: tmux attach -t $SESSION"
    tmux attach -t "$SESSION"
    exit 0
fi

if [ "$MODE" = "backend" ] || [ "$MODE" = "both" ]; then
    print "📦 Starting backend..."
    cd "$ROOT_DIR/cakra-system"
    if [ -d "venv" ]; then
        # shellcheck disable=SC1091
        source venv/bin/activate
    else
        if ! python -c 'import pkgutil,sys; sys.exit(0 if pkgutil.find_loader("sqlalchemy") else 1)' 2>/dev/null; then
            print "⚠️  Python deps missing; installing requirements (may require network)..."
            pip install -r requirements.txt
        fi
    fi

    sh -c "$BACKEND_CMD" &
    BACKEND_PID=$!
    cd "$ROOT_DIR"
    print "⏳ Waiting for backend health at http://localhost:8000/api/v1/health ..."
    if ! wait_for_http "http://localhost:8000/api/v1/health" 20; then
        print "❌ Backend did not respond in time (PID: $BACKEND_PID). Check logs."; cleanup; fi
    print "✅ Backend healthy (PID: $BACKEND_PID)"
fi

if [ "$MODE" = "frontend" ] || [ "$MODE" = "both" ]; then
    print "🌐 Starting frontend..."
    cd "$ROOT_DIR/cakra-web"
    if [ ! -d "node_modules" ]; then
        print "📦 Installing frontend dependencies (npm install)..."
        npm install
    fi
    sh -c "$FRONTEND_CMD" &
    FRONTEND_PID=$!
    cd "$ROOT_DIR"
    print "⏳ Waiting for frontend at http://localhost:5173 ..."
    if ! wait_for_http "http://localhost:5173" 20; then
        print "⚠️ Frontend did not respond in time (PID: $FRONTEND_PID). It may still be compiling."; sleep 2
    else
        print "✅ Frontend ready (PID: $FRONTEND_PID)"
    fi
fi

print "\n🎉 CAKRA started"
print "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
print "📊 Backend API: http://localhost:8000"
print "🌐 Frontend UI: http://localhost:5173"
print "📋 API Health:  http://localhost:8000/api/v1/health"
print "\n💡 Use Ctrl+C to stop both services"

wait
