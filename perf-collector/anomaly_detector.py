#!/usr/bin/env python3
"""
Spectre Attack Anomaly Detector
Detects potential Spectre-based side-channel attacks using hardware performance counters
and cache timing analysis.
"""

import json
import numpy as np
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from collections import deque
import statistics

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SpectreAnomalyDetector:
    def __init__(self, config_file: str = "metrics_config.json"):
        """Initialize Spectre anomaly detector with configuration."""
        self.config = self.load_config(config_file)
        self.performance_windows = {}
        self.cache_timing_history = deque(maxlen=1000)
        self.spectre_signatures = deque(maxlen=500)
        self.baseline_metrics = {}
        self.initialize_spectre_thresholds()
        
    def load_config(self, config_file: str) -> Dict[str, Any]:
        """Load configuration from JSON file."""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Config file {config_file} not found, using defaults")
            return self.get_default_spectre_config()
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing config file: {e}")
            return self.get_default_spectre_config()
    
    def get_default_spectre_config(self) -> Dict[str, Any]:
        """Return default configuration for Spectre detection."""
        return {
            "window_size": 100,
            "sensitivity": 1.5,
            "min_samples": 20,
            "cache_timing_threshold": 300,  # cycles
            "branch_mispredict_threshold": 0.15,  # 15% misprediction rate
            "spectre_metrics": {
                "cache_misses": {"threshold": 10000, "unit": "per_second"},
                "cache_references": {"threshold": 50000, "unit": "per_second"},
                "branch_misses": {"threshold": 5000, "unit": "per_second"},
                "branch_instructions": {"threshold": 100000, "unit": "per_second"},
                "instructions": {"threshold": 1000000, "unit": "per_second"},
                "cycles": {"threshold": 2000000, "unit": "per_second"},
                "mem_loads": {"threshold": 20000, "unit": "per_second"},
                "mem_stores": {"threshold": 15000, "unit": "per_second"},
                "llc_misses": {"threshold": 1000, "unit": "per_second"},  # Last Level Cache
                "tlb_misses": {"threshold": 500, "unit": "per_second"}    # Translation Lookaside Buffer
            }
        }
    
    def initialize_spectre_thresholds(self):
        """Initialize thresholds for Spectre-specific metrics."""
        for metric_name, config in self.config.get("spectre_metrics", {}).items():
            if metric_name not in self.performance_windows:
                self.performance_windows[metric_name] = deque(maxlen=self.config.get("window_size", 100))
    
    def add_performance_counter(self, metric_name: str, value: float, timestamp: Optional[datetime] = None) -> None:
        """Add a new performance counter value."""
        if timestamp is None:
            timestamp = datetime.now()
            
        if metric_name not in self.performance_windows:
            self.performance_windows[metric_name] = deque(maxlen=self.config.get("window_size", 100))
            
        self.performance_windows[metric_name].append({
            "value": value,
            "timestamp": timestamp
        })
    
    def calculate_cache_timing_variance(self, metric_name: str = "cache_misses") -> Tuple[bool, float]:
        """Detect unusual cache timing patterns indicative of Spectre attacks."""
        if metric_name not in self.performance_windows:
            return False, 0.0
            
        window = self.performance_windows[metric_name]
        if len(window) < self.config.get("min_samples", 20):
            return False, 0.0
            
        values = [item["value"] for item in window]
        
        # Calculate variance in cache access patterns
        if len(values) < 2:
            return False, 0.0
            
        mean = statistics.mean(values)
        variance = statistics.variance(values)
        std_dev = statistics.stdev(values)
        
        # Spectre attacks often cause irregular cache access patterns
        # High variance combined with timing irregularities can indicate attack
        baseline_variance = self.baseline_metrics.get(f"{metric_name}_variance", variance * 0.5)
        
        variance_ratio = variance / baseline_variance if baseline_variance > 0 else 1.0
        
        # Threshold for variance anomaly (attacks cause 3x+ variance increase)
        is_anomaly = variance_ratio > 3.0 and std_dev > mean * 0.3
        
        return is_anomaly, variance_ratio
    
    def detect_branch_prediction_anomalies(self) -> Tuple[bool, float]:
        """Detect branch prediction anomalies characteristic of Spectre."""
        if ("branch_misses" not in self.performance_windows or 
            "branch_instructions" not in self.performance_windows):
            return False, 0.0
            
        misses_window = self.performance_windows["branch_misses"]
        instructions_window = self.performance_windows["branch_instructions"]
        
        if (len(misses_window) < self.config.get("min_samples", 20) or 
            len(instructions_window) < self.config.get("min_samples", 20)):
            return False, 0.0
        
        # Calculate recent misprediction rate
        recent_misses = [item["value"] for item in list(misses_window)[-10:]]
        recent_instructions = [item["value"] for item in list(instructions_window)[-10:]]
        
        if len(recent_misses) == 0 or len(recent_instructions) == 0:
            return False, 0.0
            
        avg_misses = statistics.mean(recent_misses)
        avg_instructions = statistics.mean(recent_instructions)
        
        if avg_instructions == 0:
            return False, 0.0
            
        misprediction_rate = avg_misses / avg_instructions
        threshold = self.config.get("branch_mispredict_threshold", 0.15)
        
        # Spectre attacks often cause elevated branch mispredictions
        is_anomaly = misprediction_rate > threshold
        
        return is_anomaly, misprediction_rate
    
    def detect_memory_access_patterns(self) -> Tuple[bool, float]:
        """Detect unusual memory access patterns that may indicate Spectre."""
        required_metrics = ["mem_loads", "mem_stores", "llc_misses"]
        
        for metric in required_metrics:
            if metric not in self.performance_windows:
                return False, 0.0
        
        # Analyze memory access patterns
        loads = [item["value"] for item in list(self.performance_windows["mem_loads"])[-20:]]
        stores = [item["value"] for item in list(self.performance_windows["mem_stores"])[-20:]]
        llc_misses = [item["value"] for item in list(self.performance_windows["llc_misses"])[-20:]]
        
        if len(loads) < 10 or len(stores) < 10 or len(llc_misses) < 10:
            return False, 0.0
        
        # Calculate ratios that may indicate speculative execution abuse
        avg_loads = statistics.mean(loads)
        avg_stores = statistics.mean(stores)
        avg_llc_misses = statistics.mean(llc_misses)
        
        # Spectre attacks often show high load/store ratio and elevated LLC misses
        load_store_ratio = avg_loads / avg_stores if avg_stores > 0 else 0
        llc_miss_rate = avg_llc_misses / avg_loads if avg_loads > 0 else 0
        
        # Thresholds based on typical Spectre attack patterns
        suspicious_load_ratio = load_store_ratio > 5.0  # Much more loads than stores
        high_llc_miss_rate = llc_miss_rate > 0.1  # >10% LLC miss rate
        
        is_anomaly = suspicious_load_ratio and high_llc_miss_rate
        confidence = (load_store_ratio / 10.0) + (llc_miss_rate * 10.0)
        
        return is_anomaly, min(confidence, 1.0)
    
    def detect_spectre_signature(self, performance_counters: Dict[str, float]) -> Dict[str, Any]:
        """
        Main Spectre detection function using multiple indicators.
        
        Args:
            performance_counters: Dictionary of current performance counter values
            
        Returns:
            Dictionary with detection results
        """
        timestamp = datetime.now()
        
        # Add all performance counters
        for metric_name, value in performance_counters.items():
            self.add_performance_counter(metric_name, value, timestamp)
        
        results = {
            "timestamp": timestamp.isoformat(),
            "performance_counters": performance_counters,
            "spectre_indicators": {},
            "overall_spectre_risk": False,
            "risk_score": 0.0,
            "attack_type": None
        }
        
        total_score = 0.0
        indicator_count = 0
        
        # Check cache timing anomalies
        try:
            cache_anomaly, cache_score = self.calculate_cache_timing_variance("cache_misses")
            results["spectre_indicators"]["cache_timing"] = {
                "anomaly": cache_anomaly,
                "score": cache_score
            }
            if cache_anomaly:
                total_score += cache_score
            indicator_count += 1
        except Exception as e:
            logger.error(f"Error in cache timing analysis: {e}")
        
        # Check branch prediction anomalies
        try:
            branch_anomaly, branch_score = self.detect_branch_prediction_anomalies()
            results["spectre_indicators"]["branch_prediction"] = {
                "anomaly": branch_anomaly,
                "score": branch_score
            }
            if branch_anomaly:
                total_score += min(branch_score * 10, 1.0)  # Normalize score
            indicator_count += 1
        except Exception as e:
            logger.error(f"Error in branch prediction analysis: {e}")
        
        # Check memory access patterns
        try:
            memory_anomaly, memory_score = self.detect_memory_access_patterns()
            results["spectre_indicators"]["memory_access"] = {
                "anomaly": memory_anomaly,
                "score": memory_score
            }
            if memory_anomaly:
                total_score += memory_score
            indicator_count += 1
        except Exception as e:
            logger.error(f"Error in memory access analysis: {e}")
        
        # Calculate overall risk
        if indicator_count > 0:
            results["risk_score"] = total_score / indicator_count
            
            # Determine if this looks like a Spectre attack
            anomaly_count = sum(1 for indicator in results["spectre_indicators"].values() 
                              if indicator.get("anomaly", False))
            
            results["overall_spectre_risk"] = (
                anomaly_count >= 2 or  # Multiple indicators
                results["risk_score"] > 0.7  # High confidence single indicator
            )
            
            # Classify potential attack type
            if results["overall_spectre_risk"]:
                if (results["spectre_indicators"].get("branch_prediction", {}).get("anomaly", False) and
                    results["spectre_indicators"].get("cache_timing", {}).get("anomaly", False)):
                    results["attack_type"] = "Spectre-v1 (Bounds Check Bypass)"
                elif results["spectre_indicators"].get("branch_prediction", {}).get("anomaly", False):
                    results["attack_type"] = "Spectre-v2 (Branch Target Injection)"
                else:
                    results["attack_type"] = "Spectre-variant (Unknown)"
        
        # Log potential attack
        if results["overall_spectre_risk"]:
            self.log_spectre_detection(results)
            
        return results
    
    def log_spectre_detection(self, detection_result: Dict[str, Any]) -> None:
        """Log potential Spectre attack detection."""
        self.spectre_signatures.append(detection_result)
        
        logger.critical(
            f"POTENTIAL SPECTRE ATTACK DETECTED - "
            f"Risk Score: {detection_result['risk_score']:.2f}, "
            f"Type: {detection_result.get('attack_type', 'Unknown')}"
        )
        
        # Log specific indicators
        for indicator, result in detection_result["spectre_indicators"].items():
            if result.get("anomaly", False):
                logger.warning(f"  {indicator}: anomaly detected (score: {result['score']:.2f})")
    
    def update_baseline(self, performance_counters: Dict[str, float]) -> None:
        """Update baseline metrics for normal system behavior."""
        for metric_name, value in performance_counters.items():
            if metric_name in self.performance_windows:
                window = self.performance_windows[metric_name]
                if len(window) >= self.config.get("min_samples", 20):
                    values = [item["value"] for item in window]
                    self.baseline_metrics[f"{metric_name}_mean"] = statistics.mean(values)
                    self.baseline_metrics[f"{metric_name}_variance"] = statistics.variance(values)
                    
        logger.info("Baseline metrics updated")
    
    def get_spectre_history(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get history of Spectre detections."""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        history = []
        for detection in self.spectre_signatures:
            detection_time = datetime.fromisoformat(detection["timestamp"])
            if detection_time >= cutoff_time:
                history.append(detection)
                
        return history

def main():
    """Main function for testing Spectre detection."""
    detector = SpectreAnomalyDetector()
    
    # Simulate normal system behavior
    print("Establishing baseline...")
    for i in range(25):
        normal_counters = {
            "cache_misses": 5000 + np.random.normal(0, 500),
            "cache_references": 25000 + np.random.normal(0, 2000),
            "branch_misses": 2000 + np.random.normal(0, 200),
            "branch_instructions": 50000 + np.random.normal(0, 3000),
            "mem_loads": 10000 + np.random.normal(0, 1000),
            "mem_stores": 8000 + np.random.normal(0, 800),
            "llc_misses": 200 + np.random.normal(0, 50)
        }
        detector.update_baseline(normal_counters)
    
    # Simulate potential Spectre attack
    print("\nTesting with suspicious performance counters...")
    suspicious_counters = {
        "cache_misses": 15000,  # High cache misses
        "cache_references": 60000,
        "branch_misses": 8000,  # High branch mispredictions
        "branch_instructions": 45000,  # Lower total branches
        "mem_loads": 25000,  # High memory loads
        "mem_stores": 4000,   # Low memory stores (suspicious ratio)
        "llc_misses": 1500    # High LLC misses
    }
    
    result = detector.detect_spectre_signature(suspicious_counters)
    
    print("Detection Results:")
    print(f"Overall Spectre Risk: {result['overall_spectre_risk']}")
    print(f"Risk Score: {result['risk_score']:.2f}")
    print(f"Potential Attack Type: {result.get('attack_type', 'None')}")
    
    print("\nDetailed Indicators:")
    for indicator, details in result["spectre_indicators"].items():
        print(f"  {indicator}: {'ANOMALY' if details['anomaly'] else 'NORMAL'} (score: {details['score']:.2f})")

if __name__ == "__main__":
    main()
