#!/usr/bin/env bash
# Wrapper for unified startup script: start backend only
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/start-cakra.sh" --backend-only