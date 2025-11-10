#!/usr/bin/env bash
# Wrapper for unified startup script: start frontend only
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/start-cakra.sh" --frontend-only