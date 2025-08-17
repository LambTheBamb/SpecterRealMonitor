#!/usr/bin/env python3
"""
Baseline Calculator for Performance Metrics
Calculates baseline values for various system performance metrics.
"""

import json
import statistics
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BaselineCalculator:
    def __init__(self, config_file: str = "metrics_config.json"):
        """Initialize baseline calculator with configuration."""
        self.config = self.load_config(config_file)
        self.baselines = {}
        
    def load_config(self, config_file: str) -> Dict[str, Any]:
        """Load configuration from JSON file."""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Config file {config_file} not found, using defaults")
            return self.get_default_config()
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing config file: {e}")
            return self.get_default_config()
    
    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration."""
        return {
            "baseline_window_hours": 24,
            "min_samples": 10,
            "metrics": {
                "cpu_usage": {"threshold": 80.0, "unit": "percent"},
                "memory_usage": {"threshold": 85.0, "unit": "percent"},
                "disk_io": {"threshold": 1000.0, "unit": "MB/s"},
                "network_io": {"threshold": 100.0, "unit": "MB/s"},
                "power_consumption": {"threshold": 200.0, "unit": "watts"}
            }
        }
    
    def calculate_baseline(self, metric_name: str, values: List[float]) -> Dict[str, float]:
        """Calculate baseline statistics for a metric."""
        if len(values) < self.config.get("min_samples", 10):
            logger.warning(f"Insufficient samples for {metric_name}: {len(values)}")
            return {}
        
        baseline = {
            "mean": statistics.mean(values),
            "median": statistics.median(values),
            "std_dev": statistics.stdev(values) if len(values) > 1 else 0.0,
            "min": min(values),
            "max": max(values),
            "p95": self.percentile(values, 95),
            "p99": self.percentile(values, 99),
            "sample_count": len(values)
        }
        
        # Calculate dynamic threshold based on statistics
        baseline["dynamic_threshold"] = baseline["mean"] + (2 * baseline["std_dev"])
        
        return baseline
    
    def percentile(self, values: List[float], percentile: float) -> float:
        """Calculate percentile value."""
        sorted_values = sorted(values)
        k = (len(sorted_values) - 1) * percentile / 100
        f = int(k)
        c = k - f
        if f == len(sorted_values) - 1:
            return sorted_values[f]
        return sorted_values[f] * (1 - c) + sorted_values[f + 1] * c
    
    def update_baselines(self, metrics_data: Dict[str, List[float]]) -> None:
        """Update baselines with new metrics data."""
        for metric_name, values in metrics_data.items():
            if values:
                baseline = self.calculate_baseline(metric_name, values)
                if baseline:
                    self.baselines[metric_name] = baseline
                    self.baselines[metric_name]["updated_at"] = datetime.now().isoformat()
                    logger.info(f"Updated baseline for {metric_name}: mean={baseline['mean']:.2f}")
    
    def is_anomaly(self, metric_name: str, value: float) -> bool:
        """Check if a value is an anomaly based on baseline."""
        if metric_name not in self.baselines:
            return False
        
        baseline = self.baselines[metric_name]
        threshold = baseline.get("dynamic_threshold", baseline.get("mean", 0) * 1.5)
        
        return value > threshold
    
    def get_baseline_summary(self) -> Dict[str, Any]:
        """Get summary of all baselines."""
        summary = {
            "baselines": self.baselines,
            "total_metrics": len(self.baselines),
            "last_updated": datetime.now().isoformat()
        }
        return summary
    
    def save_baselines(self, filename: str = "baselines.json") -> None:
        """Save baselines to file."""
        try:
            with open(filename, 'w') as f:
                json.dump(self.baselines, f, indent=2)
            logger.info(f"Baselines saved to {filename}")
        except Exception as e:
            logger.error(f"Error saving baselines: {e}")
    
    def load_baselines(self, filename: str = "baselines.json") -> bool:
        """Load baselines from file."""
        try:
            with open(filename, 'r') as f:
                self.baselines = json.load(f)
            logger.info(f"Baselines loaded from {filename}")
            return True
        except FileNotFoundError:
            logger.info("No existing baselines file found")
            return False
        except Exception as e:
            logger.error(f"Error loading baselines: {e}")
            return False

def main():
    """Main function for testing."""
    calculator = BaselineCalculator()
    
    # Example usage
    sample_data = {
        "cpu_usage": [45.2, 52.1, 38.9, 41.0, 55.3, 47.8, 49.2, 44.1, 51.5, 46.7],
        "memory_usage": [62.1, 58.9, 65.3, 60.2, 63.8, 59.1, 61.5, 64.2, 57.8, 62.9],
        "disk_io": [125.5, 142.1, 118.9, 135.2, 128.7, 139.4, 122.3, 131.8, 126.9, 133.1]
    }
    
    calculator.update_baselines(sample_data)
    
    # Test anomaly detection
    print("Testing anomaly detection:")
    test_values = {"cpu_usage": 85.0, "memory_usage": 95.0, "disk_io": 200.0}
    
    for metric, value in test_values.items():
        is_anomaly = calculator.is_anomaly(metric, value)
        print(f"{metric}: {value} -> {'ANOMALY' if is_anomaly else 'NORMAL'}")
    
    # Print summary
    summary = calculator.get_baseline_summary()
    print(f"\nBaseline Summary:")
    print(json.dumps(summary, indent=2))

if __name__ == "__main__":
    main()
