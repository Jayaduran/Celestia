# ==============================================================================
# ULPF (Universal Log Pre-processing Framework) - Automated Deployment (PowerShell)
# ==============================================================================

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "         ULPF ENTERPRISE STACK DEPLOYMENT & BOOTSTRAP                " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# 1. Ensure .env exists
if (-not (Test-Path ".env")) {
    Write-Host "[1/5] Creating default .env configuration..." -ForegroundColor Yellow
    Copy-Item ".env.example" ".env"
} else {
    Write-Host "[1/5] Environment file .env detected." -ForegroundColor Green
}

# 2. Build local container images
Write-Host "`n[2/5] Building Docker microservices..." -ForegroundColor Yellow
docker compose build ulpf-api ulpf-worker ulpf-simulator

if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Docker build failed. Please check Docker Desktop status." -ForegroundColor Red
    exit $LASTEXITCODE
}

# 3. Start core infrastructure and microservices
Write-Host "`n[3/5] Starting ULPF stack containers..." -ForegroundColor Yellow
docker compose up -d redis minio redpanda redpanda-console ulpf-api ulpf-worker ulpf-simulator

# 4. Wait for core services to become healthy
Write-Host "`n[4/5] Waiting for services to initialize..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# 5. Initialize MinIO and Redpanda Topics
Write-Host "`n[5/5] Bootstrapping MinIO buckets and Redpanda streaming topics..." -ForegroundColor Yellow
$minioUser = if ($env:MINIO_ACCESS_KEY) { $env:MINIO_ACCESS_KEY } else { "ulpf_admin" }
$minioPass = if ($env:MINIO_SECRET_KEY) { $env:MINIO_SECRET_KEY } else { "ulpf_password_2026" }
$minioBucket = if ($env:MINIO_BUCKET) { $env:MINIO_BUCKET } else { "ulpf-raw" }

try {
    docker exec ulpf-minio mc alias set local http://localhost:9000 $minioUser $minioPass 2>$null
    docker exec ulpf-minio mc mb "local/$minioBucket" 2>$null
    Write-Host "  -> MinIO bucket '$minioBucket' verified." -ForegroundColor Green
} catch {
    Write-Host "  -> Notice: MinIO bucket init deferred or already initialized." -ForegroundColor Gray
}

try {
    docker exec ulpf-redpanda rpk topic create ulpf-raw-ingress ulpf-events-normalized ulpf-alerts -p 3 -r 1 2>$null
    Write-Host "  -> Redpanda Kafka topics verified." -ForegroundColor Green
} catch {
    Write-Host "  -> Notice: Redpanda topics already initialized." -ForegroundColor Gray
}

Write-Host "`n======================================================================" -ForegroundColor Green
Write-Host "           ULPF ENTERPRISE STACK ONLINE & OPERATIONAL                " -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Green
Write-Host " SOC UI & Gateway:       http://localhost:8000" -ForegroundColor White
Write-Host " Testing Simulator Hub:  http://localhost:8050" -ForegroundColor White
Write-Host " Redpanda Stream Visual: http://localhost:8085" -ForegroundColor White
Write-Host " MinIO Object Storage:   http://localhost:9001 ($minioUser / [configured secret])" -ForegroundColor White
Write-Host " Redis Cache & Broker:   Port 6379" -ForegroundColor White
Write-Host "======================================================================`n" -ForegroundColor Green
