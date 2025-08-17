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
