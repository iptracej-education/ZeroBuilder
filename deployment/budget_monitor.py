#!/usr/bin/env python3
"""
ZeroBuilder Budget Monitor for Vast.ai
Real-time cost tracking and automatic shutdown when budget limit reached
"""

import json
import time
import os
import sys
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional
import signal
import subprocess

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('budget_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class BudgetMonitor:
    """Monitor budget and trigger shutdown when limits reached"""
    
    def __init__(self):
        self.session_metadata = self.load_session_metadata()
        self.budget_limit = 249.77  # Total budget
        self.warning_threshold = 0.85  # 85% budget warning
        self.critical_threshold = 0.95  # 95% budget critical
        self.hourly_rate = 0.20  # RTX 8000 hourly rate
        self.monitoring = True
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        logger.info("💰 Budget Monitor initialized")
        logger.info(f"💵 Budget limit: ${self.budget_limit}")
        logger.info(f"⏱️ Hourly rate: ${self.hourly_rate}")
    
    def load_session_metadata(self) -> Dict:
        """Load session metadata from setup"""
        metadata = {}
        
        # Load from setup metadata
        if os.path.exists('/tmp/session_metadata.env'):
            with open('/tmp/session_metadata.env', 'r') as f:
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        metadata[key] = value
        
        # Load from validation session state
        if os.path.exists('session_state.json'):
            with open('session_state.json', 'r') as f:
                session_data = json.load(f)
                metadata.update(session_data)
        
        return metadata
    
    def get_current_cost(self) -> float:
        """Calculate current session cost"""
        if 'INSTANCE_START_TIME' in self.session_metadata:
            start_time = int(self.session_metadata['INSTANCE_START_TIME'])
            current_time = time.time()
            elapsed_hours = (current_time - start_time) / 3600
            return elapsed_hours * self.hourly_rate
        return 0.0
    
    def get_remaining_budget(self) -> float:
        """Get remaining budget"""
        current_cost = self.get_current_cost()
        return max(0.0, self.budget_limit - current_cost)
    
    def get_estimated_runtime_remaining(self) -> float:
        """Estimate remaining runtime in hours"""
        remaining_budget = self.get_remaining_budget()
        return remaining_budget / self.hourly_rate
    
    def check_budget_status(self) -> Dict:
        """Check current budget status"""
        current_cost = self.get_current_cost()
        remaining_budget = self.get_remaining_budget()
        budget_used_pct = (current_cost / self.budget_limit) * 100
        remaining_hours = self.get_estimated_runtime_remaining()
        
        status = "normal"
        if budget_used_pct >= self.critical_threshold * 100:
            status = "critical"
        elif budget_used_pct >= self.warning_threshold * 100:
            status = "warning"
        
        return {
            "current_cost": current_cost,
            "remaining_budget": remaining_budget,
            "budget_used_percent": budget_used_pct,
            "remaining_hours": remaining_hours,
            "status": status,
            "timestamp": datetime.now().isoformat()
        }
    
    def log_budget_status(self, status: Dict):
        """Log current budget status"""
        logger.info(f"💰 Budget Status: {status['status'].upper()}")
        logger.info(f"💵 Current cost: ${status['current_cost']:.2f}")
        logger.info(f"💸 Remaining: ${status['remaining_budget']:.2f}")
        logger.info(f"📊 Used: {status['budget_used_percent']:.1f}%")
        logger.info(f"⏱️ Est. remaining: {status['remaining_hours']:.1f} hours")
    
    def save_budget_checkpoint(self, status: Dict):
        """Save budget checkpoint"""
        checkpoint_file = f"budget_checkpoint_{int(time.time())}.json"
        with open(checkpoint_file, 'w') as f:
            json.dump(status, f, indent=2)
    
    def trigger_emergency_export(self):
        """Trigger emergency export before shutdown"""
        logger.warning("🚨 Budget limit reached - triggering emergency export")
        
        try:
            # Run pre-destroy export
            export_script = "./deployment/pre_destroy_export.sh"
            if os.path.exists(export_script):
                subprocess.run([export_script], check=True)
                logger.info("✅ Emergency export completed")
            else:
                logger.warning("⚠️ Export script not found")
                
        except Exception as e:
            logger.error(f"❌ Emergency export failed: {e}")
    
    def trigger_instance_shutdown(self):
        """Trigger instance shutdown"""
        logger.critical("🛑 BUDGET LIMIT EXCEEDED - SHUTTING DOWN INSTANCE")
        
        # Create shutdown marker
        with open('/tmp/budget_shutdown_triggered', 'w') as f:
            f.write(f"Budget shutdown triggered at {datetime.now().isoformat()}\n")
            f.write(f"Final cost: ${self.get_current_cost():.2f}\n")
        
        # Attempt graceful shutdown
        try:
            subprocess.run(["sudo", "shutdown", "-h", "+1", "Budget limit reached"], check=True)
            logger.info("✅ Shutdown scheduled in 1 minute")
        except Exception as e:
            logger.error(f"❌ Shutdown failed: {e}")
            # Force exit
            sys.exit(1)
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"📡 Received signal {signum} - shutting down monitor")
        self.monitoring = False
    
    def run_monitoring_loop(self):
        """Main monitoring loop"""
        logger.info("🔄 Starting budget monitoring loop")
        
        check_interval = 60  # Check every minute
        warning_sent = False
        
        while self.monitoring:
            try:
                status = self.check_budget_status()
                
                # Log status every 5 minutes
                if int(time.time()) % 300 == 0:
                    self.log_budget_status(status)
                
                # Handle budget thresholds
                if status['status'] == 'critical':
                    if not warning_sent:
                        logger.critical("🚨 CRITICAL: Budget at 95% - shutdown imminent")
                        warning_sent = True
                    
                    # Trigger shutdown if budget exceeded
                    if status['budget_used_percent'] >= 100:
                        self.trigger_emergency_export()
                        self.trigger_instance_shutdown()
                        break
                        
                elif status['status'] == 'warning':
                    if not warning_sent:
                        logger.warning("⚠️ WARNING: Budget at 85%")
                        warning_sent = True
                
                # Save checkpoint every 10 minutes
                if int(time.time()) % 600 == 0:
                    self.save_budget_checkpoint(status)
                
                time.sleep(check_interval)
                
            except KeyboardInterrupt:
                logger.info("👋 Monitoring stopped by user")
                break
            except Exception as e:
                logger.error(f"❌ Monitoring error: {e}")
                time.sleep(check_interval)
        
        logger.info("🏁 Budget monitoring ended")

def main():
    """Main budget monitor"""
    if len(sys.argv) > 1 and sys.argv[1] == "--status":
        # One-time status check
        monitor = BudgetMonitor()
        status = monitor.check_budget_status()
        monitor.log_budget_status(status)
        
        # Exit with appropriate code
        if status['status'] == 'critical':
            sys.exit(2)
        elif status['status'] == 'warning':
            sys.exit(1)
        else:
            sys.exit(0)
    else:
        # Continuous monitoring
        monitor = BudgetMonitor()
        monitor.run_monitoring_loop()

if __name__ == "__main__":
    main()