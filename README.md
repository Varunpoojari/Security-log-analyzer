# Security Log Anomaly Detector

A Python-based security log analyzer that detects anomalies in security logs. This tool helps identify suspicious patterns such as multiple failed login attempts from the same IP address.

## Features

- Load and parse JSON-formatted security logs
- Detect suspicious login patterns
- Identify potential security threats
- Simple and extensible design

## Setup

1. Clone the repository:
```bash
git clone https://github.com/Varunpoojari/security-log-analyzer.git
cd security-log-analyzer
```

2. Create and activate virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install pandas
```

## Usage

1. Prepare your log file in JSON Lines format (one JSON object per line) and save it as `security_logs.json` — the included file is a working example
2. Run the analyzer:
```bash
python log_analyzer.py
```

## Sample Log Format

Each log entry should be a JSON object with the following structure:
```json
{
    "timestamp": "2024-02-02T10:00:00",
    "event_type": "login_attempt",
    "source_ip": "192.168.1.100",
    "status": "failed"
}
```
