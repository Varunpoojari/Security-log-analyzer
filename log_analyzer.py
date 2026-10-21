import json
from datetime import datetime

import pandas as pd

REQUIRED_COLUMNS = ("event_type", "status", "source_ip")


class SecurityLogAnalyzer:
    """
    A basic security log analyzer that can detect simple anomalies in log files.
    This class will grow more sophisticated as we add more features.
    """

    def __init__(self, failed_login_threshold=5):
        """
        Initialize the analyzer with basic settings

        Args:
            failed_login_threshold (int): An IP address is flagged when it has
                more than this many failed login attempts.
        """
        self.log_data = None
        self.anomalies = []
        self.failed_login_threshold = failed_login_threshold

    def load_log_file(self, file_path):
        """
        Load a log file for analysis

        The file must be in JSON Lines format (one JSON object per line).
        Blank lines are ignored.

        Args:
            file_path (str): Path to the log file

        Returns:
            bool: True if the file was loaded, False otherwise.
        """
        records = []
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                for line_number, line in enumerate(file, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        print(
                            f"Error loading log file: invalid JSON on line "
                            f"{line_number}: {e.msg}"
                        )
                        return False
        except OSError as e:
            print(f"Error loading log file: {e}")
            return False

        self.log_data = pd.DataFrame(records)
        return True

    def detect_basic_anomalies(self):
        """
        Detect basic anomalies in the logs:
        - IP addresses with many failed login attempts

        Each call re-analyzes the loaded data and replaces the previous
        findings, so calling it more than once does not duplicate anomalies.

        Returns:
            list[dict]: The detected anomalies, or the string
            "No log data loaded" if no log file has been loaded.

        Raises:
            ValueError: If the log data has entries but is missing a column
                the analysis needs.
        """
        if self.log_data is None:
            return "No log data loaded"

        self.anomalies = []
        if self.log_data.empty:
            return self.anomalies

        missing = [c for c in REQUIRED_COLUMNS if c not in self.log_data.columns]
        if missing:
            raise ValueError(
                f"Log data is missing required column(s): {', '.join(missing)}"
            )

        # Look for failed login attempts
        failed_logins = self.log_data[
            (self.log_data["event_type"] == "login_attempt")
            & (self.log_data["status"] == "failed")
        ]

        # Group by IP address to find suspicious activity
        ip_counts = failed_logins["source_ip"].value_counts()
        suspicious_ips = ip_counts[ip_counts > self.failed_login_threshold].index.tolist()

        # Record findings
        for ip in suspicious_ips:
            self.anomalies.append({
                "type": "suspicious_login_attempts",
                "ip_address": ip,
                "count": int(ip_counts[ip]),
                "timestamp": datetime.now().isoformat()
            })

        return self.anomalies

if __name__ == "__main__":
    analyzer = SecurityLogAnalyzer()
    print("Starting security log analysis...")

    # Load and analyze the log file
    if analyzer.load_log_file("security_logs.json"):
        print("Log file loaded successfully!")
        anomalies = analyzer.detect_basic_anomalies()

        if anomalies:
            print("\nDetected Anomalies:")
            for anomaly in anomalies:
                print(f"\nSuspicious activity from IP: {anomaly['ip_address']}")
                print(f"Number of failed attempts: {anomaly['count']}")
                print(f"Detected at: {anomaly['timestamp']}")
        else:
            print("\nNo anomalies detected")
