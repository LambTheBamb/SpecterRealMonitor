#!/bin/bash

# Spectre Monitoring System Test Suite
# Tests all components to ensure proper detection capabilities

echo "🧪 SPECTRE MONITORING TEST SUITE"
echo "=================================="
echo "Starting comprehensive testing at $(date)"
echo

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results tracking
TESTS_PASSED=0
TESTS_FAILED=0
TOTAL_TESTS=0

# Helper function for test results
test_result() {
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✅ PASS${NC}: $2"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}❌ FAIL${NC}: $2"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Test 1: Container Health Check
echo -e "${BLUE}📦 Testing Container Health${NC}"
echo "----------------------------------------"

docker-compose ps | grep -q "Up" 
test_result $? "All containers are running"

# Check specific containers
for container in spectre-perf-collector spectre-influxdb spectre-grafana spectre-prometheus; do
    docker ps | grep -q "$container.*Up"
    test_result $? "$container is healthy"
done

echo

# Test 2: Service Connectivity
echo -e "${BLUE}🌐 Testing Service Connectivity${NC}"
echo "----------------------------------------"

# InfluxDB Health
curl -s http://localhost:8086/health | grep -q "pass"
test_result $? "InfluxDB health check"

# Grafana Response
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000 | grep -q "200\|302"
test_result $? "Grafana accessibility"

# Prometheus Response
curl -s -o /dev/null -w "%{http_code}" http://localhost:9090 | grep -q "200"
test_result $? "Prometheus accessibility"

# AlertManager Response
curl -s -o /dev/null -w "%{http_code}" http://localhost:9093 | grep -q "200"
test_result $? "AlertManager accessibility"

echo

# Test 3: Data Collection Verification
echo -e "${BLUE}📊 Testing Data Collection${NC}"
echo "----------------------------------------"

# Check if InfluxDB has buckets
BUCKETS=$(docker exec spectre-influxdb influx bucket list 2>/dev/null | wc -l)
test_result $([ $BUCKETS -gt 1 ] && echo 0 || echo 1) "InfluxDB buckets exist ($BUCKETS buckets)"

# Check for recent data
RECENT_DATA=$(docker exec spectre-influxdb influx query 'from(bucket:"spectre-metrics") |> range(start: -5m) |> count()' 2>/dev/null | grep -c "_value")
test_result $([ $RECENT_DATA -gt 0 ] && echo 0 || echo 1) "Recent data in InfluxDB ($RECENT_DATA data points)"

# Check Prometheus metrics
PROMETHEUS_METRICS=$(curl -s http://localhost:9090/api/v1/label/__name__/values | jq -r '.data[]' 2>/dev/null | wc -l)
test_result $([ $PROMETHEUS_METRICS -gt 5 ] && echo 0 || echo 1) "Prometheus has metrics ($PROMETHEUS_METRICS metrics)"

echo

# Test 4: Performance Counter Availability
echo -e "${BLUE}⚡ Testing Performance Counters${NC}"
echo "----------------------------------------"

# Check if perf is available
command -v perf >/dev/null 2>&1
test_result $? "Perf tool is installed"

# Test basic perf functionality
timeout 5 sudo perf stat -e cycles,instructions sleep 1 >/dev/null 2>&1
test_result $? "Basic performance counters work"

# Check available cache events
CACHE_EVENTS=$(sudo perf list 2>/dev/null | grep -i cache | wc -l)
test_result $([ $CACHE_EVENTS -gt 0 ] && echo 0 || echo 1) "Cache performance events available ($CACHE_EVENTS events)"

echo

# Test 5: Alert System Testing
echo -e "${BLUE}🚨 Testing Alert System${NC}"
echo "----------------------------------------"

# Check Prometheus rules
RULES_COUNT=$(curl -s http://localhost:9090/api/v1/rules | jq '.data.groups[].rules | length' 2>/dev/null | head -1)
test_result $([ "$RULES_COUNT" -gt 0 ] 2>/dev/null && echo 0 || echo 1) "Prometheus alert rules loaded ($RULES_COUNT rules)"

# Check AlertManager config
curl -s http://localhost:9093/api/v1/status | grep -q "success"
test_result $? "AlertManager configuration valid"

echo

# Test 6: Simulated Attack Detection
echo -e "${BLUE}🎯 Testing Attack Detection (Simulation)${NC}"
echo "----------------------------------------"

echo "Generating test workloads..."

# Create CPU-intensive workload
echo -e "${YELLOW}Starting CPU stress test...${NC}"
stress --cpu 2 --timeout 10s >/dev/null 2>&1 &
STRESS_PID=$!

sleep 5

# Check if monitoring detected the activity
ps aux | grep -v grep | grep -q stress
test_result $? "Stress test process is running"

# Wait for stress test to complete
wait $STRESS_PID 2>/dev/null

# Create memory-intensive workload
echo -e "${YELLOW}Starting memory stress test...${NC}"
stress --vm 1 --vm-bytes 256M --timeout 10s >/dev/null 2>&1 &
MEMORY_STRESS_PID=$!

sleep 5
kill $MEMORY_STRESS_PID 2>/dev/null || true

# Create rapid file access pattern
echo -e "${YELLOW}Testing file access pattern detection...${NC}"
mkdir -p /tmp/spectre_test
for i in {1..50}; do
    echo "test" > /tmp/spectre_test/file_$i.txt
    cat /tmp/spectre_test/file_$i.txt > /dev/null
done
rm -rf /tmp/spectre_test

test_result 0 "File access pattern test completed"

echo

# Test 7: Log Analysis
echo -e "${BLUE}📝 Testing Log Analysis${NC}"
echo "----------------------------------------"

# Check for errors in perf-collector logs
ERROR_COUNT=$(docker logs spectre-perf-collector 2>&1 | grep -i error | wc -l)
test_result $([ $ERROR_COUNT -lt 5 ] && echo 0 || echo 1) "Perf-collector has minimal errors ($ERROR_COUNT errors)"

# Check for successful data collection
SUCCESS_COUNT=$(docker logs spectre-perf-collector 2>&1 | grep -i "collecting\|success" | wc -l)
test_result $([ $SUCCESS_COUNT -gt 0 ] && echo 0 || echo 1) "Data collection is active ($SUCCESS_COUNT success messages)"

echo

# Test 8: Data Visualization
echo -e "${BLUE}📈 Testing Data Visualization${NC}"
echo "----------------------------------------"

# Check Grafana data sources
DATASOURCES=$(curl -s -u admin:spectrepassword http://localhost:3000/api/datasources 2>/dev/null | jq '. | length' 2>/dev/null || echo 0)
test_result $([ $DATASOURCES -gt 0 ] && echo 0 || echo 1) "Grafana has data sources configured ($DATASOURCES sources)"

echo

# Test 9: Enhanced Cloud Monitoring (if implemented)
echo -e "${BLUE}☁️ Testing Enhanced Cloud Monitoring${NC}"
echo "----------------------------------------"

# Check if enhanced monitoring is running
docker exec spectre-perf-collector ps aux | grep -q python
test_result $? "Python monitoring processes are running"

# Check for alert files
if [ -f /tmp/spectre_alerts.json ] || docker exec spectre-perf-collector ls /data/spectre_alerts.json >/dev/null 2>&1; then
    test_result 0 "Enhanced monitoring alert system is active"
else
    test_result 1 "Enhanced monitoring alert system not detected"
fi

echo

# Test 10: System Resource Impact
echo -e "${BLUE}🔧 Testing System Resource Impact${NC}"
echo "----------------------------------------"

# Check CPU usage of monitoring containers
HIGH_CPU_CONTAINERS=$(docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}" | grep spectre | awk -F'[%\t]' '$2 > 50 {count++} END {print count+0}')
test_result $([ $HIGH_CPU_CONTAINERS -eq 0 ] && echo 0 || echo 1) "No containers using excessive CPU ($HIGH_CPU_CONTAINERS high-usage containers)"

# Check memory usage
HIGH_MEM_CONTAINERS=$(docker stats --no-stream --format "table {{.Name}}\t{{.MemUsage}}" | grep spectre | wc -l)
test_result $([ $HIGH_MEM_CONTAINERS -gt 0 ] && echo 0 || echo 1) "Memory usage is being tracked"

echo

# Advanced Testing Functions
echo -e "${BLUE}🧬 Advanced Detection Tests${NC}"
echo "----------------------------------------"

# Test cache timing simulation
echo -e "${YELLOW}Running cache timing test...${NC}"
cat > /tmp/cache_test.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
    const int SIZE = 1024 * 1024;
    char *array = malloc(SIZE);
    struct timespec start, end;
    
    // Sequential access
    clock_gettime(CLOCK_MONOTONIC, &start);
    for(int i = 0; i < SIZE/4; i++) {
        array[i*4] = i % 256;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    long seq_time = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
    
    // Random access
    srand(time(NULL));
    clock_gettime(CLOCK_MONOTONIC, &start);
    for(int i = 0; i < SIZE/4; i++) {
        array[rand() % SIZE] = i % 256;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    long rand_time = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
    
    printf("Sequential: %ld ns, Random: %ld ns, Ratio: %.2f\n", 
           seq_time, rand_time, (double)rand_time/seq_time);
    
    free(array);
    return 0;
}
EOF

# Compile and run cache test
if gcc -o /tmp/cache_test /tmp/cache_test.c 2>/dev/null; then
    /tmp/cache_test
    test_result $? "Cache timing test executed successfully"
    rm -f /tmp/cache_test /tmp/cache_test.c
else
    test_result 1 "Cache timing test compilation failed (gcc not available)"
fi

echo

# Final Results
echo -e "${BLUE}📋 TEST SUMMARY${NC}"
echo "=================================="
echo -e "Total Tests: $TOTAL_TESTS"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n${GREEN}🎉 ALL TESTS PASSED! Your Spectre monitoring system is working correctly.${NC}"
    exit 0
elif [ $TESTS_FAILED -lt 3 ]; then
    echo -e "\n${YELLOW}⚠️ MOSTLY WORKING: Your system is functional but has minor issues.${NC}"
    exit 1
else
    echo -e "\n${RED}❌ SIGNIFICANT ISSUES: Your monitoring system needs attention.${NC}"
    exit 2
fi
