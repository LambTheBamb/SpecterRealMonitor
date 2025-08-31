# /home/specter-monitor/perf-collector/enhanced_cloud_monitor.py

import psutil
import time
import json
import logging
import threading
from collections import defaultdict, deque
from datetime import datetime
import subprocess
import os

class EnhancedCloudSpectreMonitor:
    """
    Enhanced Spectre detection for cloud environments where hardware PMU access is limited.
    Focuses on software-based timing analysis and behavioral patterns.
    """
    
    def __init__(self, config=None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Data structures for pattern analysis
        self.cpu_usage_history = defaultdict(lambda: deque(maxlen=60))
        self.memory_patterns = defaultdict(lambda: deque(maxlen=100))
        self.timing_anomalies = defaultdict(list)
        self.process_creation_times = defaultdict(list)
        
        # Thresholds (configurable)
        self.cpu_spike_threshold = self.config.get('cpu_spike_threshold', 3.0)
        self.memory_growth_threshold = self.config.get('memory_growth_mb', 100)
        self.rapid_process_threshold = self.config.get('rapid_process_count', 5)
        
        # Monitoring flags
        self.running = False
        self.threads = []
    
    def start_monitoring(self):
        """Start all monitoring threads"""
        self.running = True
        
        # Start monitoring threads
        monitors = [
            ('CPU Spike Monitor', self._monitor_cpu_spikes),
            ('Memory Pattern Monitor', self._monitor_memory_patterns),
            ('Process Behavior Monitor', self._monitor_process_behavior),
            ('System Call Monitor', self._monitor_system_calls),
            ('File Access Monitor', self._monitor_file_access),
        ]
        
        for name, func in monitors:
            thread = threading.Thread(target=func, name=name, daemon=True)
            thread.start()
            self.threads.append(thread)
            self.logger.info(f"Started {name}")
    
    def stop_monitoring(self):
        """Stop all monitoring"""
        self.running = False
        self.logger.info("Stopping enhanced monitoring...")
    
    def _monitor_cpu_spikes(self):
        """Monitor for sudden CPU usage spikes that might indicate side-channel attacks"""
        while self.running:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                    try:
                        pid = proc.info['pid']
                        cpu = proc.info['cpu_percent']
                        name = proc.info['name']
                        
                        # Track CPU usage history
                        self.cpu_usage_history[pid].append(cpu)
                        
                        # Analyze for spikes
                        if len(self.cpu_usage_history[pid]) > 10:
                            recent_avg = sum(list(self.cpu_usage_history[pid])[-10:]) / 10
                            
                            # Detect sudden spikes
                            if cpu > recent_avg * self.cpu_spike_threshold and cpu > 50:
                                alert = {
                                    'timestamp': datetime.now().isoformat(),
                                    'alert_type': 'cpu_spike',
                                    'pid': pid,
                                    'process_name': name,
                                    'cpu_percent': cpu,
                                    'recent_average': recent_avg,
                                    'severity': 'medium'
                                }
                                self._send_alert(alert)
                                
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                        
            except Exception as e:
                self.logger.error(f"CPU monitoring error: {e}")
            
            time.sleep(1)
    
    def _monitor_memory_patterns(self):
        """Monitor for unusual memory allocation patterns"""
        while self.running:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                    try:
                        pid = proc.info['pid']
                        memory_mb = proc.info['memory_info'].rss / (1024 * 1024)
                        name = proc.info['name']
                        
                        # Track memory usage
                        self.memory_patterns[pid].append(memory_mb)
                        
                        # Detect rapid memory growth
                        if len(self.memory_patterns[pid]) > 5:
                            recent_growth = memory_mb - self.memory_patterns[pid][-6]
                            
                            if recent_growth > self.memory_growth_threshold:
                                alert = {
                                    'timestamp': datetime.now().isoformat(),
                                    'alert_type': 'memory_anomaly',
                                    'pid': pid,
                                    'process_name': name,
                                    'memory_growth_mb': recent_growth,
                                    'current_memory_mb': memory_mb,
                                    'severity': 'high' if recent_growth > 500 else 'medium'
                                }
                                self._send_alert(alert)
                                
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                        
            except Exception as e:
                self.logger.error(f"Memory monitoring error: {e}")
            
            time.sleep(2)
    
    def _monitor_process_behavior(self):
        """Monitor process creation patterns for suspicious behavior"""
        while self.running:
            try:
                current_time = time.time()
                current_processes = set(p.pid for p in psutil.process_iter())
                
                # Track process creation timing
                for pid in current_processes:
                    if pid not in self.process_creation_times:
                        self.process_creation_times[pid] = current_time
                
                # Clean old entries
                cutoff_time = current_time - 60  # Keep last 60 seconds
                self.process_creation_times = {
                    pid: create_time for pid, create_time in self.process_creation_times.items()
                    if create_time > cutoff_time and pid in current_processes
                }
                
                # Check for rapid process creation (potential attack pattern)
                recent_processes = [
                    create_time for create_time in self.process_creation_times.values()
                    if current_time - create_time < 10  # Last 10 seconds
                ]
                
                if len(recent_processes) > self.rapid_process_threshold:
                    alert = {
                        'timestamp': datetime.now().isoformat(),
                        'alert_type': 'rapid_process_creation',
                        'process_count': len(recent_processes),
                        'time_window': '10_seconds',
                        'severity': 'high'
                    }
                    self._send_alert(alert)
                    
            except Exception as e:
                self.logger.error(f"Process behavior monitoring error: {e}")
            
            time.sleep(5)
    
    def _monitor_system_calls(self):
        """Monitor system calls for timing anomalies (requires strace)"""
        if not self.running:
            return
            
        try:
            # Monitor high-frequency system calls that might indicate timing attacks
            cmd = ['strace', '-e', 'trace=read,write,open,close', '-f', '-p', '1', '-T']
            
            # This is a simplified version - in practice you'd monitor specific processes
            self.logger.info("System call monitoring would require specific process targeting")
            
        except Exception as e:
            self.logger.warning(f"System call monitoring unavailable: {e}")
    
    def _monitor_file_access(self):
        """Monitor file access patterns using inotify"""
        try:
            # Monitor common attack vectors
            watch_paths = ['/tmp', '/var/tmp', '/dev/shm']
            
            for path in watch_paths:
                if os.path.exists(path):
                    # In a real implementation, you'd use pyinotify or similar
                    self.logger.info(f"Would monitor file access patterns in {path}")
                    
        except Exception as e:
            self.logger.error(f"File access monitoring error: {e}")
    
    def _send_alert(self, alert_data):
        """Send alert to your existing alerting system"""
        try:
            # Log the alert
            self.logger.warning(f"SPECTRE ALERT: {alert_data}")
            
            # Here you would integrate with your existing InfluxDB/Prometheus alerting
            # For now, we'll write to a file that your main collector can read
            alert_file = '/data/spectre_alerts.json'
            
            try:
                with open(alert_file, 'a') as f:
                    json.dump(alert_data, f)
                    f.write('\n')
            except Exception as e:
                self.logger.error(f"Failed to write alert: {e}")
                
        except Exception as e:
            self.logger.error(f"Alert sending failed: {e}")
    
    def get_metrics_summary(self):
        """Get current monitoring metrics"""
        return {
            'active_processes': len(self.cpu_usage_history),
            'memory_tracked_processes': len(self.memory_patterns),
            'recent_process_creations': len([
                t for t in self.process_creation_times.values() 
                if time.time() - t < 60
            ]),
            'monitoring_uptime': time.time() if self.running else 0
        }

# Integration with existing anomaly_detector.py
def integrate_enhanced_monitoring():
    """Function to be called from your existing anomaly_detector.py"""
    
    config = {
        'cpu_spike_threshold': 3.0,
        'memory_growth_mb': 100,
        'rapid_process_count': 5
    }
    
    monitor = EnhancedCloudSpectreMonitor(config)
    monitor.start_monitoring()
    
    return monitor

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Start enhanced monitoring
    monitor = integrate_enhanced_monitoring()
    
    try:
        # Keep running
        while True:
            time.sleep(60)
            summary = monitor.get_metrics_summary()
            logging.info(f"Monitoring summary: {summary}")
            
    except KeyboardInterrupt:
        monitor.stop_monitoring()
        logging.info("Enhanced monitoring stopped")
