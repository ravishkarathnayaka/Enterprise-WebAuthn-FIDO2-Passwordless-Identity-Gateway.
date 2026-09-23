"""Unit tests for telemetry metrics collector and rate limiter."""

import time

from gateway.middleware.rate_limit import InMemoryRateLimiter
from gateway.middleware.telemetry import MetricsCollector


def test_metrics_collector_ceremony_counters():
    collector = MetricsCollector()
    assert collector.registration_requests_total == 0

    collector.record_registration()
    collector.record_registration()
    assert collector.registration_requests_total == 2

    collector.record_authentication("success")
    collector.record_authentication("success")
    collector.record_authentication("failed")
    assert collector.authentication_attempts_total["success"] == 2
    assert collector.authentication_attempts_total["failed"] == 1

    collector.record_counter_replay_violation()
    assert collector.counter_replay_violations_total == 1

    collector.record_step_up("success")
    assert collector.step_up_challenges_total["success"] == 1


def test_metrics_collector_http_duration_and_output():
    collector = MetricsCollector()
    collector.record_http_request("POST", "/api/auth/login/verify", 200, 0.045)
    collector.record_http_request("POST", "/api/auth/login/verify", 200, 0.055)
    collector.record_http_request("GET", "/health", 200, 0.002)

    output = collector.generate_prometheus_metrics()
    assert "webauthn_registration_requests_total 0" in output
    assert "webauthn_counter_replay_violations_total 0" in output
    assert "gateway_http_requests_total" in output
    assert 'gateway_http_requests_total{method="POST",path="/api/auth/login/verify",status="200"} 2' in output


def test_rate_limiter_permits_under_threshold():
    limiter = InMemoryRateLimiter(max_requests=3, window_seconds=10)
    client_ip = "192.168.1.50"

    allowed1, retry1 = limiter.is_allowed(client_ip)
    assert allowed1 is True
    assert retry1 == 0

    allowed2, retry2 = limiter.is_allowed(client_ip)
    assert allowed2 is True
    assert retry2 == 0

    allowed3, retry3 = limiter.is_allowed(client_ip)
    assert allowed3 is True
    assert retry3 == 0

    # 4th request must be throttled
    allowed4, retry4 = limiter.is_allowed(client_ip)
    assert allowed4 is False
    assert retry4 > 0
    assert retry4 <= 10


def test_rate_limiter_distinct_ips():
    limiter = InMemoryRateLimiter(max_requests=1, window_seconds=10)
    assert limiter.is_allowed("10.0.0.1")[0] is True
    assert limiter.is_allowed("10.0.0.1")[0] is False
    # Distinct IP is allowed
    assert limiter.is_allowed("10.0.0.2")[0] is True


def test_rate_limiter_window_expiry(monkeypatch):
    current_time = 1000.0
    monkeypatch.setattr(time, "time", lambda: current_time)

    limiter = InMemoryRateLimiter(max_requests=2, window_seconds=5)
    assert limiter.is_allowed("1.2.3.4")[0] is True
    assert limiter.is_allowed("1.2.3.4")[0] is True
    assert limiter.is_allowed("1.2.3.4")[0] is False

    # Fast forward past window
    current_time = 1006.0
    allowed, retry = limiter.is_allowed("1.2.3.4")
    assert allowed is True
    assert retry == 0
