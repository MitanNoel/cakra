#!/usr/bin/env bash
# Compatibility wrapper: delegate to unified `start-cakra.sh`
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/start-cakra.sh" "$@"