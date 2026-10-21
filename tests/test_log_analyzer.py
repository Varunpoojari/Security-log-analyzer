import json

import pytest

from log_analyzer import SecurityLogAnalyzer


def event(ip="10.0.0.1", status="failed", event_type="login_attempt"):
    return {
        "timestamp": "2024-02-02T10:00:00",
        "event_type": event_type,
        "source_ip": ip,
        "status": status,
    }


def write_logs(path, events, trailing=""):
    path.write_text("\n".join(json.dumps(e) for e in events) + trailing)
    return str(path)


@pytest.fixture
def loaded(tmp_path):
    """Build an analyzer loaded with the given events."""

    def _loaded(events, **kwargs):
        analyzer = SecurityLogAnalyzer(**kwargs)
        assert analyzer.load_log_file(write_logs(tmp_path / "logs.json", events))
        return analyzer

    return _loaded


def test_sample_log_flags_the_attacking_ip():
    analyzer = SecurityLogAnalyzer()
    assert analyzer.load_log_file("security_logs.json")

    anomalies = analyzer.detect_basic_anomalies()

    assert len(anomalies) == 1
    assert anomalies[0]["type"] == "suspicious_login_attempts"
    assert anomalies[0]["ip_address"] == "192.168.1.100"
    assert anomalies[0]["count"] == 6


def test_threshold_is_exclusive(loaded):
    at_threshold = loaded([event() for _ in range(5)])
    over_threshold = loaded([event() for _ in range(6)])

    assert at_threshold.detect_basic_anomalies() == []
    assert len(over_threshold.detect_basic_anomalies()) == 1


def test_custom_threshold(loaded):
    analyzer = loaded([event() for _ in range(3)], failed_login_threshold=2)

    anomalies = analyzer.detect_basic_anomalies()

    assert [a["count"] for a in anomalies] == [3]


def test_only_failed_login_attempts_are_counted(loaded):
    events = (
        [event(status="success") for _ in range(10)]
        + [event(event_type="file_access") for _ in range(10)]
        + [event() for _ in range(3)]
    )

    assert loaded(events).detect_basic_anomalies() == []


def test_failures_are_counted_per_ip(loaded):
    events = (
        [event(ip="10.0.0.1") for _ in range(6)]
        + [event(ip="10.0.0.2") for _ in range(7)]
        + [event(ip="10.0.0.3") for _ in range(4)]
    )

    anomalies = loaded(events).detect_basic_anomalies()

    assert {a["ip_address"]: a["count"] for a in anomalies} == {
        "10.0.0.1": 6,
        "10.0.0.2": 7,
    }


def test_count_is_a_plain_int_and_results_are_json_serializable(loaded):
    anomalies = loaded([event() for _ in range(6)]).detect_basic_anomalies()

    assert type(anomalies[0]["count"]) is int
    json.dumps(anomalies)


def test_calling_detect_twice_does_not_duplicate_anomalies(loaded):
    analyzer = loaded([event() for _ in range(6)])

    analyzer.detect_basic_anomalies()
    second = analyzer.detect_basic_anomalies()

    assert len(second) == 1
    assert len(analyzer.anomalies) == 1


def test_detect_before_loading_returns_message():
    assert SecurityLogAnalyzer().detect_basic_anomalies() == "No log data loaded"


def test_blank_lines_are_ignored(tmp_path):
    path = write_logs(tmp_path / "logs.json", [event() for _ in range(6)], trailing="\n\n")
    analyzer = SecurityLogAnalyzer()

    assert analyzer.load_log_file(path)
    assert len(analyzer.detect_basic_anomalies()) == 1


def test_invalid_json_reports_the_line_number(tmp_path, capsys):
    path = tmp_path / "logs.json"
    path.write_text(json.dumps(event()) + "\n{not json}\n")
    analyzer = SecurityLogAnalyzer()

    assert analyzer.load_log_file(str(path)) is False
    assert "line 2" in capsys.readouterr().out


def test_missing_file_returns_false(tmp_path, capsys):
    analyzer = SecurityLogAnalyzer()

    assert analyzer.load_log_file(str(tmp_path / "nope.json")) is False
    assert "Error loading log file" in capsys.readouterr().out


def test_empty_file_has_no_anomalies(tmp_path):
    path = tmp_path / "logs.json"
    path.write_text("")
    analyzer = SecurityLogAnalyzer()

    assert analyzer.load_log_file(str(path))
    assert analyzer.detect_basic_anomalies() == []


def test_missing_required_column_raises_clear_error(tmp_path):
    path = tmp_path / "logs.json"
    path.write_text(json.dumps({"timestamp": "t", "message": "hello"}) + "\n")
    analyzer = SecurityLogAnalyzer()
    assert analyzer.load_log_file(str(path))

    with pytest.raises(ValueError, match="missing required column.*event_type"):
        analyzer.detect_basic_anomalies()
