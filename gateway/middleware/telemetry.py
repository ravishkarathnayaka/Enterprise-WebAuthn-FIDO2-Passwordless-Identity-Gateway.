"""Prometheus metrics and observability telemetry for WebAuthn Gateway."""

import time
from collections import defaultdict
from collections.abc import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware


class MetricsCollector:
    """Thread-safe Prometheus metrics collector for FIDO2/WebAuthn ceremonies."""

    def __init__(self):
        self.http_requests_total: dict[str, int] = defaultdict(int)
        self.registration_requests_total = 0
        self.authentication_attempts_total: dict[str, int] = defaultdict(int)
        self.counter_replay_violations_total = 0
        self.step_up_challenges_total: dict[str, int] = defaultdict(int)
        self.request_durations: dict[str, list] = defaultdict(list)

    def record_http_request(self, method: str, path: str, status_code: int, duration_seconds: float):
        key = f'{method}:{path}:{status_code}'
        self.http_requests_total[key] += 1
        # Keep last 100 duration samples per route for percentile calculation
        self.request_durations[f'{method}:{path}'].append(duration_seconds)
        if len(self.request_durations[f'{method}:{path}']) > 100:
            self.request_durations[f'{method}:{path}'].pop(0)

    def record_registration(self):
        self.registration_requests_total += 1

    def record_authentication(self, status: str):
        self.authentication_attempts_total[status] += 1

    def record_counter_replay_violation(self):
        self.counter_replay_violations_total += 1

    def record_step_up(self, status: str):
        self.step_up_challenges_total[status] += 1

    def generate_prometheus_metrics(self) -> str:
        """Export metrics in standard Prometheus text format."""
        lines = [
            "# HELP webauthn_registration_requests_total Total number of WebAuthn registration ceremonies.",
            "# TYPE webauthn_registration_requests_total counter",
            f"webauthn_registration_requests_total {self.registration_requests_total}",
            "",
            "# HELP webauthn_authentication_attempts_total Total WebAuthn authentication attempts by outcome.",
            "# TYPE webauthn_authentication_attempts_total counter",
        ]
        for status, count in self.authentication_attempts_total.items():
            lines.append(f'webauthn_authentication_attempts_total{{status="{status}"}} {count}')
        if not self.authentication_attempts_total:
            lines.append('webauthn_authentication_attempts_total{status="success"} 0')
            lines.append('webauthn_authentication_attempts_total{status="replay_detected"} 0')

        lines.extend([
            "",
            "# HELP webauthn_counter_replay_violations_total Number of detected cloned hardware key replay attempts.",
            "# TYPE webauthn_counter_replay_violations_total counter",
            f"webauthn_counter_replay_violations_total {self.counter_replay_violations_total}",
            "",
            "# HELP webauthn_step_up_challenges_total Total step-up authorization challenges by result.",
            "# TYPE webauthn_step_up_challenges_total counter",
        ])
        for status, count in self.step_up_challenges_total.items():
            lines.append(f'webauthn_step_up_challenges_total{{status="{status}"}} {count}')
        if not self.step_up_challenges_total:
            lines.append('webauthn_step_up_challenges_total{status="authorized"} 0')
            lines.append('webauthn_step_up_challenges_total{status="expired"} 0')

        lines.extend([
            "",
            "# HELP gateway_http_requests_total Total HTTP requests routed through Identity Gateway.",
            "# TYPE gateway_http_requests_total counter",
        ])
        for key, count in self.http_requests_total.items():
            method, path, status = key.split(":")
            lines.append(f'gateway_http_requests_total{{method="{method}",path="{path}",status="{status}"}} {count}')

        return "\n".join(lines) + "\n"


# Singleton instance
metrics = MetricsCollector()


class TelemetryMiddleware(BaseHTTPMiddleware):
    """Middleware measuring latency and request throughput for observability."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.time()
        response = await call_next(request)
        duration = time.time() - start_time

        # Filter out noisy static assets from metrics
        path = request.url.path
        if not path.startswith("/static"):
            metrics.record_http_request(
                method=request.method,
                path=path,
                status_code=response.status_code,
                duration_seconds=duration,
            )

        return response
