#!/usr/bin/env python3

import os
import sys
import time
import json
import subprocess
import logging
import threading
from datetime import datetime
from typing import Dict, List, Optional
import psutil
import numpy as np
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SpectreMetricsCollector:
    def __init__(self):
        self.influx_client = None
        self.write_api = None
        self.setup_influxdb()
        self.load_config()
        self.baseline_data = {}
        self.anomaly_threshold = 3.0  # Standard deviations
        
    def setup_influxdb(self):
        """Initialize InfluxDB connection"""
        try:
            url = os.getenv('INFLUXDB_URL', 'http://127.0.0.1:8086')
            token = os.getenv('INFLUXDB_TOKEN', 'your-influxdb-token')
            org = os.getenv('INFLUXDB_ORG', 'spectre-monitoring')
            
            self.influx_client = InfluxDBClient(url=url, token=token, org=org)
            self.write_api = self.influx_client.write_api(write_options=SYNCHRONOUS)
            logger.info("InfluxDB connection established")
        except Exception as e:
            logger.error(f"Failed to connect to InfluxDB: {e}")
            sys.exit(1)
    
    def load_config(self):
        """Load metrics configuration"""
        try:
            with open('/app/metrics_config.json', 'r') as f:
                self.config = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            # Use default config
            self.config = self.get_default_config()
    
    def get_default_config(self):
        """Default metrics configuration"""
        return {
            "cache_metrics": [
                "cache-misses",
                "cache-references",
                "LLC-load-misses",
                "LLC-store-misses",
                "L1-dcache-load-misses",
                "L1-icache-load-misses",
                "dTLB-load-misses",
                "iTLB-load-misses"
            ],
            "branch_metrics": [
                "branch-misses",
                "branches",
                "branch-load-misses"
            ],
            "memory_metrics": [
                "mem_load_retired.l3_miss",
                "mem_load_retired.l2_miss",
                "mem_load_retired.l1_miss",
                "mem_inst_retired.all_loads",
                "mem_inst_retired.all_stores"
            ],
            "execution_metrics": [
                "cycles",
                "instructions",
                "stalled-cycles-frontend",
                "stalled-cycles-backend",
                "cpu-clock",
                "task-clock"
            ],
            "speculative_metrics": [
                "uops_retired.retire_slots",
                "uops_issued.any",
                "int_misc.recovery_cycles",
                "machine_clears.count"
            ]
        }
    
    def run_perf_command(self, events: List[str], duration: int = 1) -> Dict:
        """Execute perf stat command and parse results"""
        try:
            # Join events with commas
            event_string = ','.join(events)
            
            # Build perf command
            cmd = [
                'perf', 'stat',
                '-e', event_string,
                '-x', ',',  # CSV output
                '-I', str(duration * 1000),  # Interval in milliseconds
                '--', 'sleep', str(duration)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 5)
            
            if result.returncode != 0:
                logger.warning(f"Perf command failed: {result.stderr}")
                return {}
            
            return self.parse_perf_output(result.stderr)
            
        except subprocess.TimeoutExpired:
            logger.error("Perf command timed out")
            return {}
        except Exception as e:
            logger.error(f"Error running perf command: {e}")
            return {}
    
    def parse_perf_output(self, output: str) -> Dict:
        """Parse perf stat CSV output"""
        metrics = {}
        lines = output.strip().split('\n')
        
        for line in lines:
            if not line or line.startswith('#'):
                continue
                
            parts = line.split(',')
            if len(parts) >= 3:
                try:
                    # Format: timestamp,value,event_name
                    timestamp = parts[0]
                    value_str = parts[1]
                    event_name = parts[2]
                    
                    # Handle 'not supported' or empty values
                    if value_str and value_str != '<not supported>' and value_str != '<not counted>':
                        value = float(value_str)
                        metrics[event_name] = {
                            'value': value,
                            'timestamp': timestamp
                        }
                except (ValueError, IndexError) as e:
                    logger.debug(f"Failed to parse line: {line}, error: {e}")
                    continue
        
        return metrics
    
    def collect_system_metrics(self) -> Dict:
        """Collect additional system metrics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            load_avg = os.getloadavg()
            
            return {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_available': memory.available,
                'load_1min': load_avg[0],
                'load_5min': load_avg[1],
                'load_15min': load_avg[2]
            }
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            return {}
    
    def detect_anomalies(self, current_metrics: Dict) -> List[Dict]:
        """Detect anomalies in current metrics"""
        anomalies = []
        
        for metric_name, metric_data in current_metrics.items():
            if metric_name not in self.baseline_data:
                continue
                
            current_value = metric_data.get('value', 0)
            baseline = self.baseline_data[metric_name]
            
            mean = baseline.get('mean', 0)
            std = baseline.get('std', 1)
            
            if std > 0:
                z_score = abs((current_value - mean) / std)
                if z_score > self.anomaly_threshold:
                    anomalies.append({
                        'metric': metric_name,
                        'current_value': current_value,
                        'baseline_mean': mean,
                        'z_score': z_score,
                        'severity': 'high' if z_score > 5 else 'medium'
                    })
        
        return anomalies
    
    def update_baseline(self, metrics: Dict):
        """Update baseline statistics for metrics"""
        for metric_name, metric_data in metrics.items():
            value = metric_data.get('value', 0)
            
            if metric_name not in self.baseline_data:
                self.baseline_data[metric_name] = {
                    'values': [],
                    'mean': 0,
                    'std': 1
                }
            
            baseline = self.baseline_data[metric_name]
            baseline['values'].append(value)
            
            # Keep only last 1000 values for baseline
            if len(baseline['values']) > 1000:
                baseline['values'] = baseline['values'][-1000:]
            
            # Update statistics if we have enough data
            if len(baseline['values']) >= 10:
                baseline['mean'] = np.mean(baseline['values'])
                baseline['std'] = max(np.std(baseline['values']), 0.1)  # Minimum std
    
    def write_to_influxdb(self, metrics: Dict, anomalies: List[Dict]):
        """Write metrics and anomalies to InfluxDB"""
        try:
            points = []
            timestamp = datetime.utcnow()
            
            # Write performance metrics
            for metric_name, metric_data in metrics.items():
                if isinstance(metric_data, dict) and 'value' in metric_data:
                    point = Point("spectre_metrics") \
                        .tag("metric_type", self.get_metric_type(metric_name)) \
                        .tag("metric_name", metric_name) \
                        .field("value", float(metric_data['value'])) \
                        .time(timestamp, WritePrecision.S)
                    points.append(point)
                elif isinstance(metric_data, (int, float)):
                    point = Point("system_metrics") \
                        .tag("metric_name", metric_name) \
                        .field("value", float(metric_data)) \
                        .time(timestamp, WritePrecision.S)
                    points.append(point)
            
            # Write anomalies
            for anomaly in anomalies:
                point = Point("spectre_anomalies") \
                    .tag("metric", anomaly['metric']) \
                    .tag("severity", anomaly['severity']) \
                    .field("current_value", anomaly['current_value']) \
                    .field("baseline_mean", anomaly['baseline_mean']) \
                    .field("z_score", anomaly['z_score']) \
                    .time(timestamp, WritePrecision.S)
                points.append(point)
            
            if points:
                bucket = os.getenv('INFLUXDB_BUCKET', 'spectre-metrics')
                self.write_api.write(bucket=bucket, record=points)
                logger.info(f"Written {len(points)} points to InfluxDB")
                
        except Exception as e:
            logger.error(f"Error writing to InfluxDB: {e}")
    
    def get_metric_type(self, metric_name: str) -> str:
        """Categorize metric by type"""
        if any(cache_metric in metric_name.lower() for cache_metric in ['cache', 'llc', 'l1', 'l2', 'l3', 'tlb']):
            return 'cache'
        elif any(branch_metric in metric_name.lower() for branch_metric in ['branch']):
            return 'branch'
        elif any(mem_metric in metric_name.lower() for mem_metric in ['mem_', 'memory']):
            return 'memory'
        elif any(spec_metric in metric_name.lower() for spec_metric in ['uops', 'machine_clear', 'recovery']):
            return 'speculative'
        else:
            return 'execution'
    
    def collect_all_metrics(self):
        """Collect all configured metrics"""
        all_metrics = {}
        
        # Collect each category of metrics
        for category, events in self.config.items():
            if events:
                logger.info(f"Collecting {category}: {events}")
                category_metrics = self.run_perf_command(events)
                all_metrics.update(category_metrics)
        
        # Add system metrics
        system_metrics = self.collect_system_metrics()
        all_metrics.update(system_metrics)
        
        return all_metrics
    
    def run(self):
        """Main collection loop"""
        logger.info("Starting Spectre metrics collection")
        
        interval = int(os.getenv('COLLECTION_INTERVAL', '1'))
        
        while True:
            try:
                # Collect metrics
                metrics = self.collect_all_metrics()
                
                if not metrics:
                    logger.warning("No metrics collected")
                    time.sleep(interval)
                    continue
                
                # Update baseline data
                self.update_baseline(metrics)
                
                # Detect anomalies
                anomalies = self.detect_anomalies(metrics)
                
                if anomalies:
                    logger.warning(f"Detected {len(anomalies)} anomalies")
                    for anomaly in anomalies:
                        logger.warning(f"Anomaly in {anomaly['metric']}: "
                                     f"current={anomaly['current_value']:.2f}, "
                                     f"z_score={anomaly['z_score']:.2f}")
                
                # Write to InfluxDB
                self.write_to_influxdb(metrics, anomalies)
                
                logger.info(f"Collected {len(metrics)} metrics, {len(anomalies)} anomalies")
                
            except KeyboardInterrupt:
                logger.info("Shutting down collector")
                break
            except Exception as e:
                logger.error(f"Error in collection loop: {e}")
            
            time.sleep(interval)
        
        # Cleanup
        if self.influx_client:
            self.influx_client.close()

if __name__ == "__main__":
    collector = SpectreMetricsCollector()
    collector.run()
