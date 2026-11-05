#!/usr/bin/env bash
# ==============================================================================
# ULPF (Universal Log Pre-processing Framework) - Automated Stack Deployment
# Compatible with: Linux (Ubuntu, Debian, Oracle Linux, RHEL), macOS, and Cloud VMs
# ==============================================================================
set -e

# ANSI Color Codes
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "======================================================================"
echo "         ULPF ENTERPRISE STACK DEPLOYMENT & BOOTSTRAP                "
echo "======================================================================"
echo -e "${NC}"

# ------------------------------------------------------------------------------
# 1. Docker Runtime & Privilege Detection
# ------------------------------------------------------------------------------
echo -e "${YELLOW}[1/6] Validating Docker environment and privileges...${NC}"

if ! command -v docker >/dev/null 2>&1; then
    echo -e "${RED}[ERROR] Docker is not installed or not in PATH.${NC}"
    echo -e "${YELLOW}Please install Docker Engine and Docker Compose before deploying:${NC}"
    echo -e "  sudo apt update && sudo apt install -y docker.io docker-compose-plugin"
    exit 1
fi

# Detect whether sudo is required for docker
DOCKER_CMD="docker"
if ! docker info >/dev/null 2>&1; then
    if command -v sudo >/dev/null 2>&1 && sudo docker info >/dev/null 2>&1; then
        echo -e "${YELLOW}[INFO] Docker daemon requires elevated privileges. Using sudo...${NC}"
        DOCKER_CMD="sudo docker"
    else
        echo -e "${RED}[ERROR] Cannot connect to Docker daemon.${NC}"
        echo -e "Please start Docker or add your user to the 'docker' group:"
        echo -e "  sudo usermod -aG docker \$USER && newgrp docker"
        exit 1
    fi
fi

# Detect Docker Compose command
COMPOSE_CMD=""
if $DOCKER_CMD compose version >/dev/null 2>&1; then
    COMPOSE_CMD="$DOCKER_CMD compose"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
else
    echo -e "${RED}[ERROR] Docker Compose plugin is missing.${NC}"
    echo -e "${YELLOW}Please install docker-compose-plugin (e.g. sudo apt install docker-compose-plugin)${NC}"
    exit 1
fi
echo -e "${GREEN}[OK] Docker engine and compose confirmed: $($COMPOSE_CMD version)${NC}"

# ------------------------------------------------------------------------------
# 2. Kernel & Host Optimizations (OpenSearch vm.max_map_count check)
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[2/6] Verifying system kernel parameters...${NC}"
if [ -f /proc/sys/vm/max_map_count ]; then
    CURRENT_MAP=$(cat /proc/sys/vm/max_map_count 2>/dev/null || echo "65530")
    if [ "$CURRENT_MAP" -lt 262144 ]; then
        echo -e "${YELLOW}[WARN] vm.max_map_count ($CURRENT_MAP) is below 262144 (required by OpenSearch).${NC}"
        if [ "$EUID" -eq 0 ] || command -v sudo >/dev/null 2>&1; then
            echo -e "${BLUE}[INFO] Increasing vm.max_map_count to 262144...${NC}"
            sudo sysctl -w vm.max_map_count=262144 >/dev/null 2>&1 || true
        else
            echo -e "${YELLOW}Please run: sudo sysctl -w vm.max_map_count=262144${NC}"
        fi
    else
        echo -e "${GREEN}[OK] vm.max_map_count is ${CURRENT_MAP}.${NC}"
    fi
fi

# ------------------------------------------------------------------------------
# 3. Environment File Configuration & Public IP Detection
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[3/6] Configuring application environment...${NC}"

# Detect Public IP if on Cloud VM
DETECTED_IP="localhost"
if command -v curl >/dev/null 2>&1; then
    DETECTED_IP=$(curl -s -m 2 http://169.254.169.254/opc/v1/instance/ | grep -oE '"canonicalRegionName": "[^"]+"' >/dev/null 2>&1 && curl -s -m 2 https://ifconfig.me || true)
    if [ -z "$DETECTED_IP" ]; then
        DETECTED_IP=$(curl -s -m 2 https://ifconfig.me 2>/dev/null || curl -s -m 2 https://api.ipify.org 2>/dev/null || echo "localhost")
    fi
fi

if [ ! -f ".env" ]; then
    echo -e "${BLUE}[INFO] Creating default .env configuration from .env.example...${NC}"
    cp .env.example .env
else
    echo -e "${GREEN}[OK] Environment file .env detected.${NC}"
fi

# Update OCI_PUBLIC_IP in .env if detected
if [ -n "$DETECTED_IP" ] && [ "$DETECTED_IP" != "localhost" ]; then
    if grep -q "^OCI_PUBLIC_IP=" .env; then
        sed -i "s/^OCI_PUBLIC_IP=.*/OCI_PUBLIC_IP=${DETECTED_IP}/" .env
    else
        echo "OCI_PUBLIC_IP=${DETECTED_IP}" >> .env
    fi
    echo -e "${GREEN}[OK] Configured external host / public IP: ${DETECTED_IP}${NC}"
fi

# ------------------------------------------------------------------------------
# 4. Build Container Microservices
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[4/6] Building ULPF Docker microservices...${NC}"
$COMPOSE_CMD build ulpf-api ulpf-worker ulpf-simulator

# ------------------------------------------------------------------------------
# 5. Launch Stack Containers
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[5/6] Starting ULPF stack containers in detached mode...${NC}"
$COMPOSE_CMD up -d redis minio redpanda redpanda-console ulpf-api ulpf-worker ulpf-simulator

# ------------------------------------------------------------------------------
# 6. Service Health Polling & Dynamic Bootstrapping
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[6/6] Polling service health and bootstrapping topics & storage...${NC}"

# A. Poll MinIO & Initialize Bucket
MINIO_USER="${MINIO_ACCESS_KEY:-$(grep -E '^MINIO_ACCESS_KEY=' .env 2>/dev/null | cut -d= -f2 || echo 'ulpf_admin')}"
MINIO_PASS="${MINIO_SECRET_KEY:-$(grep -E '^MINIO_SECRET_KEY=' .env 2>/dev/null | cut -d= -f2 || echo 'ulpf_password_2026')}"
MINIO_BUCKET_NAME="${MINIO_BUCKET:-$(grep -E '^MINIO_BUCKET=' .env 2>/dev/null | cut -d= -f2 || echo 'ulpf-raw')}"

echo -n "  -> Awaiting MinIO object storage ready: "
MINIO_READY=false
for i in {1..35}; do
    if $DOCKER_CMD exec ulpf-minio mc alias set local http://localhost:9000 "$MINIO_USER" "$MINIO_PASS" >/dev/null 2>&1; then
        MINIO_READY=true
        break
    fi
    echo -n "."
    sleep 2
done

if [ "$MINIO_READY" = true ]; then
    $DOCKER_CMD exec ulpf-minio mc mb "local/${MINIO_BUCKET_NAME}" >/dev/null 2>&1 || true
    echo -e " ${GREEN}[HEALTHY]${NC} (Bucket '${MINIO_BUCKET_NAME}' verified)"
else
    echo -e " ${YELLOW}[INITIALIZING]${NC} (MinIO still initializing in background)"
fi

# B. Poll Redpanda & Initialize Streaming Topics
echo -n "  -> Awaiting Redpanda Kafka bus ready: "
REDPANDA_READY=false
for i in {1..35}; do
    if $DOCKER_CMD exec ulpf-redpanda rpk cluster info >/dev/null 2>&1; then
        REDPANDA_READY=true
        break
    fi
    echo -n "."
    sleep 2
done

if [ "$REDPANDA_READY" = true ]; then
    $DOCKER_CMD exec ulpf-redpanda rpk topic create ulpf-raw-ingress ulpf-events-normalized ulpf-alerts -p 3 -r 1 >/dev/null 2>&1 || true
    echo -e " ${GREEN}[HEALTHY]${NC} (Topics created: ingress, normalized, alerts)"
else
    echo -e " ${YELLOW}[INITIALIZING]${NC} (Redpanda still initializing in background)"
fi

# C. Poll ULPF FastAPI Gateway
echo -n "  -> Awaiting ULPF SOC Ingestion API ready: "
API_READY=false
for i in {1..25}; do
    if curl -s -f http://127.0.0.1:8000/api/v1/health/live >/dev/null 2>&1; then
        API_READY=true
        break
    fi
    echo -n "."
    sleep 2
done

if [ "$API_READY" = true ]; then
    echo -e " ${GREEN}[ONLINE]${NC}"
else
    echo -e " ${YELLOW}[STARTING]${NC}"
fi

# D. Poll Simulator Hub
echo -n "  -> Awaiting Protocol Simulator Hub ready: "
SIM_READY=false
for i in {1..20}; do
    if curl -s -f http://127.0.0.1:8050/ >/dev/null 2>&1; then
        SIM_READY=true
        break
    fi
    echo -n "."
    sleep 2
done

if [ "$SIM_READY" = true ]; then
    echo -e " ${GREEN}[ONLINE]${NC}"
else
    echo -e " ${YELLOW}[STARTING]${NC}"
fi

# ------------------------------------------------------------------------------
# Final Operations Summary
# ------------------------------------------------------------------------------
echo -e "\n${GREEN}${BOLD}======================================================================${NC}"
echo -e "${GREEN}${BOLD}           ULPF ENTERPRISE STACK ONLINE & OPERATIONAL                ${NC}"
echo -e "${GREEN}${BOLD}======================================================================${NC}"
echo -e " SOC Web Dashboard:      http://${DETECTED_IP}:8000/dashboard/index.html (Local: http://localhost:8000)"
echo -e " REST API & OpenAPI Docs:http://${DETECTED_IP}:8000/docs"
echo -e " Testing Simulator Hub:  http://${DETECTED_IP}:8050/ (Local: http://localhost:8050)"
echo -e " Redpanda Stream Visual: http://${DETECTED_IP}:8085/ (Local: http://localhost:8085)"
echo -e " MinIO Object Storage:   http://${DETECTED_IP}:9001/ (${MINIO_USER} / [configured secret])"
echo -e " Syslog Collectors:      ${DETECTED_IP}:5140 (UDP) | ${DETECTED_IP}:5141 (TCP)"
echo -e " Redis In-Memory Broker: Port 6379"
echo -e "${GREEN}======================================================================${NC}"
if [ "$DETECTED_IP" != "localhost" ]; then
    echo -e "${YELLOW}${BOLD}ORACLE CLOUD SECURITY REMINDER:${NC}"
    echo -e "Ensure VCN Ingress Rules allow TCP ports 8000, 8050, 8085, 9001, 5141 and UDP 5140."
    echo -e "${GREEN}======================================================================${NC}"
fi
echo -e " Run verification test:  python3 scripts/verify_stack.py\n"
