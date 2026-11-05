#!/bin/sh
set -e

# Start Ollama server in background
/bin/ollama serve &
pid=$!

# Wait for Ollama server to be responsive
echo "[ULPF-AI] Initializing Ollama AI Engine..."
for i in $(seq 1 30); do
    if curl -s http://127.0.0.1:11434/api/tags > /dev/null 2>&1; then
        echo "[ULPF-AI] Ollama service connected."
        break
    fi
    sleep 1
done

# Pull configured model if specified
MODEL="${OLLAMA_MODEL:-qwen2.5-coder:3b}"
if [ -n "$MODEL" ]; then
    echo "[ULPF-AI] Ensuring LLM model is downloaded: $MODEL..."
    ollama pull "$MODEL" || echo "[ULPF-AI] Notice: Model pull deferred or offline."
fi

echo "[ULPF-AI] Sovereign Local LLM service is online on port 11434."
wait $pid
