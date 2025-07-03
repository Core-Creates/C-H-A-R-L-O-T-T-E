#!/bin/bash
# Usage: ./scripts/launch_burp_service.sh
# Launch the Burp plugin Java service
#
# Assumes:
# - JAR_FILE is built by Gradle and located in the dist directory.
# - PY4J_JAR is located in libs directory.
# Adjust paths accordingly.

set -e

# ==========================================================
# CONFIG
# ==========================================================
DIST_DIR="$(pwd)/dist"
LIB_DIR="$(pwd)/libs"

JAR_NAME="burp-helper-1.0.0.jar"
PY4J_NAME="py4j0.10.9.7.jar"

JAR_FILE="${DIST_DIR}/${JAR_NAME}"
PY4J_JAR="${LIB_DIR}/${PY4J_NAME}"

# ==========================================================
# PREREQUISITES
# ==========================================================
if ! command -v java &> /dev/null; then
    echo "[!] Java is not installed or not in PATH. Please install or add to PATH."
    exit 1
fi

if [ ! -f "$JAR_FILE" ]; then
    echo "[!] JAR not found at ${JAR_FILE}. Run 'gradle build' first."
    exit 1
fi

if [ ! -f "$PY4J_JAR" ]; then
    echo "[!] Py4J JAR not found at ${PY4J_JAR}. Check your libs directory."
    exit 1
fi

# ==========================================================
# START SERVICE
# ==========================================================
echo "[*] Launching BurpHelper service..."
if java -cp "${JAR_FILE}:${PY4J_JAR}" com.charlotte.BurpHelper; then
    echo "[*] BurpHelper service started successfully."
else
    echo "[!] Failed to start BurpHelper service."
    exit 1
fi
