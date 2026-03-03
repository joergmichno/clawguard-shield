"""
ClawGuard Shield — Data Models
Request/Response dataclasses for the API.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ScanRequest:
    """Incoming scan request."""
    text: str
    source: str = "api"

    def validate(self, max_length: int = 5000) -> Optional[str]:
        """Validate the request. Returns error message or None."""
        if not self.text or not self.text.strip():
            return "Field 'text' is required and must not be empty."
        if len(self.text) > max_length:
            return f"Text exceeds maximum length of {max_length:,} characters. Your text: {len(self.text):,} chars."
        return None


@dataclass
class ScanResponse:
    """API scan response."""
    clean: bool
    risk_score: int
    severity: str
    findings_count: int
    findings: list = field(default_factory=list)
    scan_time_ms: int = 0
    api_version: str = "1.0"

    def to_dict(self) -> dict:
        return {
            "clean": self.clean,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "findings_count": self.findings_count,
            "findings": self.findings,
            "scan_time_ms": self.scan_time_ms,
            "api_version": self.api_version,
        }


@dataclass
class RegisterRequest:
    """API key registration request."""
    email: str

    def validate(self) -> Optional[str]:
        """Validate the registration. Returns error message or None."""
        if not self.email or not self.email.strip():
            return "Field 'email' is required."
        # Basic email format check
        if "@" not in self.email or "." not in self.email.split("@")[-1]:
            return "Invalid email format."
        if len(self.email) > 254:
            return "Email address too long."
        return None


@dataclass
class HealthResponse:
    """Health check response."""
    status: str = "healthy"
    service: str = "clawguard-shield"
    version: str = "1.0.0"
    patterns_count: int = 0

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "service": self.service,
            "version": self.version,
            "patterns_count": self.patterns_count,
        }
