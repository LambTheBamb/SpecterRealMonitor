#!/bin/bash

# Setup script for Spectre Monitoring Environment
set -e

echo "🚀 Setting up Spectre Monitoring Environment..."

# Create directory structure
echo "📁 Creating directory structure..."
mkdir -p perf-collector
mkdir -p grafana/provisioning/datasources
mkdir -p grafana/provisioning/dashboards  
mkdir -p grafana/dashboards
mkdir -p alertmanager
mkdir -p prometheus
mkdir -p data

# Create perf-collector files
echo "📄 Creating collector files..."

# Create Dockerfile for perf-collector
cat > perf-collector/Dockerfile << 'EOF'
FROM ubuntu:22.04

# Install required packages
RUN apt-get update && apt-get install -y \
    linux-tools-generic \
    linux-tools-common \
    python3 \
    python3-pip \
    curl \
    wget \
    build-essential \
    git \
    cmake \
    libpfm4-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip3 install \
    influxdb-client \
    psutil \
    numpy \
    scipy \
    requests \
    prometheus-client

# Install PAPI (Performance Application Programming Interface)
RUN cd /tmp && \
    wget http://icl.utk.edu/projects/papi/downloads/papi-7.0.1.tar.gz && \
    tar -xzf papi-7.0.1.tar.gz && \
    cd papi-7.0.1/src && \
    ./configure && \
    make && \
    make install && \
    ldconfig

# Install Intel PCM (if on Intel hardware)
RUN cd /tmp && \
    git clone https://github.com/intel/pcm.git && \
    cd pcm && \
    make && \
    cp pcm*.x /usr/local/bin/ || true

# Create working directory
WORKDIR /app

# Copy collector scripts
COPY collector.py /app/
COPY metrics_config.json /app/
COPY entrypoint.sh /app/
COPY baseline_calculator.py /app/
COPY anomaly_detector.py /app/

# Make scripts executable
RUN chmod +x /app/entrypoint.sh

# Set up perf for container use
RUN echo 'kernel.perf_event_paranoid = -1' >> /etc/sysctl.conf
RUN echo 'kernel.kptr_restrict = 0' >> /etc/sysctl.conf

ENTRYPOINT ["/app/entrypoint.sh"]
EOF

# Copy the Python files (these would be created from the artifacts above)
echo "⚠️  You need to copy the following files to the perf-collector directory:"
echo "   - collector.py"
echo "   - metrics_config.json" 
echo "   - entrypoint.sh"

# Create Grafana provisioning files
echo "📊 Creating Grafana configuration..."

cat > grafana/provisioning/datasources/influxdb.yml << 'EOF'
apiVersion: 1

datasources:
  - name: InfluxDB
    type: influxdb
    access: proxy
    url: http://influxdb:8086
    user: admin
    database: spectre-metrics
    basicAuth: false
    isDefault: true
    jsonData:
      version: Flux
      organization: spectre-monitoring
      defaultBucket: spectre-metrics
      tlsSkipVerify: true
    secureJsonData:
      token: your-influxdb-token
    editable: true
EOF

cat > grafana/provisioning/dashboards/dashboards.yml << 'EOF'
apiVersion: 1

providers:
  - name: 'Spectre Monitoring'
    orgId: 1
    folder: 'Spectre Security'
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    allowUiUpdates: true
    options:
      path: /var/lib/grafana/dashboards
EOF

# Create AlertManager configuration
echo "🚨 Creating AlertManager configuration..."
cat > alertmanager/alertmanager.yml << 'EOF'
global:
  smtp_smarthost: 'localhost:587'
  smtp_from: 'alerts@spectre-monitoring.local'

route:
  group_by: ['alertname']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'web.hook'

receivers:
- name: 'web.hook'
  webhook_configs:
  - url: 'http://localhost:5001/'

inhibit_rules:
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname', 'dev', 'instance']
EOF

# Create Prometheus configuration
echo "📈 Creating Prometheus configuration..."
cat > prometheus/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'spectre-collector'
    static_configs:
      - targets: ['perf-collector:8000']

rule_files:
  - "spectre_rules.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
EOF

# Create Prometheus alerting rules
cat > prometheus/spectre_rules.yml << 'EOF'
groups:
- name: spectre.rules
  rules:
  - alert: HighCacheMissRate
    expr: cache_miss_rate > 0.1
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High cache miss rate detected"
      description: "Cache miss rate is {{ $value }}%, which may indicate Spectre-like behavior"

  - alert: AnomalousMemoryAccess
    expr: mem_load_retired_l3_miss > 1000
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "Anomalous memory access pattern"
      description: "L3 cache misses: {{ $value }}/sec"

  - alert: SpeculativeExecutionAnomaly
    expr: machine_clears_count > 100
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Speculative execution anomaly detected"
      description: "Machine clears: {{ $value }}/sec"
EOF

# Create test script
echo "🧪 Creating test script..."
cat > test_setup.sh << 'EOF'
#!/bin/bash

echo "🧪 Testing Spectre Monitoring Setup..."

# Test Docker Compose
echo "Testing Docker Compose..."
docker-compose config > /dev/null && echo "✓ docker-compose.yml is valid" || echo "❌ docker-compose.yml has errors"

# Test perf availability
echo "Testing perf availability..."
if command -v perf &> /dev/null; then
    echo "✓ perf is available"
    perf list | head -5
else
    echo "❌ perf not found - install linux-tools-$(uname -r)"
fi

# Test required events
echo "Testing key performance events..."
EVENTS=("cache-misses" "cache-references" "branch-misses" "cycles")
for event in "${EVENTS[@]}"; do
    if perf list | grep -q "$event"; then
        echo "✓ $event is available"
    else
        echo "⚠️  $event may not be available"
    fi
done

# Check system permissions
echo "Checking system permissions..."
if [ $(cat /proc/sys/kernel/perf_event_paranoid) -gt 1 ]; then
    echo "⚠️  perf_event_paranoid = $(cat /proc/sys/kernel/perf_event_paranoid)"
    echo "   Consider: echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid"
else
    echo "✓ perf_event_paranoid is properly configured"
fi

echo "🏁 Test complete!"
EOF

chmod +x test_setup.sh

echo ""
echo "✅ Setup complete!"
echo ""
echo "📋 Next steps:"
echo "1. Copy the Python files to perf-collector/ directory"
echo "2. Copy the dashboard JSON to grafana/dashboards/"
echo "3. Run: ./test_setup.sh"
echo "4. Run: docker-compose up -d"
echo "5. Access Grafana at http://localhost:3000 (admin/spectrepassword)"
echo ""
echo "🔧 Required files to copy:"
echo "   - collector.py → perf-collector/"
echo "   - metrics_config.json → perf-collector/"
echo "   - entrypoint.sh → perf-collector/"
echo "   - spectre-dashboard.json → grafana/dashboards/"
