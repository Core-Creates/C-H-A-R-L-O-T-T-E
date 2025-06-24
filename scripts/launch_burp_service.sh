#!/bin/bash
# Usage: ./scripts/launch_burp_service.sh
# Launch the Burp plugin Java service

set -e
JAR_FILE=$(pwd)/dist/burp-helper-1.0.0.jar
PY4J_JAR=$(pwd)/libs/py4j0.10.9.7.jar  # Adjust path accordingly

if [ ! -f "$JAR_FILE" ]; then
  echo "[!] JAR not found. Run 'gradle build' first."
  exit 1
fi

echo "[*] Launching BurpHelper service..."
java -cp "$JAR_FILE:$PY4J_JAR" com.charlotte.BurpHelper
if [ $? -eq 0 ]; then
  echo "[*] BurpHelper service started successfully."
else
  echo "[!] Failed to start BurpHelper service."
  exit 1
fi