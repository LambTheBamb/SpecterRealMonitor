#!/bin/bash

set -e

echo "Starting Spectre Metrics Collector..."

# Set kernel parameters for perf access
echo -1 > /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo "Cannot set perf_event_paranoid (may need privileged mode)"
echo 0 > /proc/sys/kernel/kptr_restrict 2>/dev/null || echo "Cannot set kptr_restrict"

# Check if perf is available
if ! command -v perf &> /dev/null; then
    echo "ERROR: perf command not found"
    exit 1
fi

# Test perf access
echo "Testing perf access..."
if perf stat -e cycles -- sleep 0.1 2>/dev/null; then
    echo "✓ Perf access OK"
else
    echo "⚠ Perf access limited - some metrics may not be available"
    echo "  Make sure container runs with --privileged flag"
fi

# Check for Intel-specific events
echo "Checking CPU architecture and available events..."
ARCH=$(uname -m)
echo "Architecture: $ARCH"

# List available events (limited output)
echo "Available performance events:"
perf list cache 2>/dev/null | head -20 || echo "Cannot list cache events"

# Wait for InfluxDB to be ready
echo "Waiting for InfluxDB..."
until curl -f "${INFLUXDB_URL:-http://influxdb:8086}/ping" >/dev/null 2>&1; do
    echo "Waiting for InfluxDB to be ready..."
    sleep 5
done
echo "✓ InfluxDB is ready"

# Create data directory
mkdir -p /data

# Start the collector
echo "Starting Python collector..."
cd /app
python3 collector.py
