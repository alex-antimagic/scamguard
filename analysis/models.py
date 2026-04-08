from dataclasses import dataclass, field
from enum import Enum


class AddressType(str, Enum):
    URL = 'url'
    PHONE = 'phone'
    WHATSAPP = 'whatsapp'
    INSTAGRAM = 'instagram'
    UNKNOWN = 'unknown'


class Severity(str, Enum):
    CRITICAL = 'critical'
    HIGH = 'high'
    MEDIUM = 'medium'
    LOW = 'low'
    INFO = 'info'


SEVERITY_SCORES = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 25,
    Severity.MEDIUM: 15,
    Severity.LOW: 5,
    Severity.INFO: 0,
}


@dataclass
class Finding:
    analyzer: str
    check: str
    severity: Severity
    detail: str

    def to_dict(self):
        return {
            'analyzer': self.analyzer,
            'check': self.check,
            'severity': self.severity.value,
            'detail': self.detail,
        }


@dataclass
class AnalysisResult:
    address_raw: str
    address_normalized: str
    address_type: AddressType
    risk_score: int = 0
    verdict: str = 'safe'
    findings: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    analysis_time_ms: int = 0

    def to_dict(self):
        return {
            'address': {
                'raw': self.address_raw,
                'normalized': self.address_normalized,
                'type': self.address_type.value,
            },
            'risk_score': self.risk_score,
            'verdict': self.verdict,
            'findings': [f.to_dict() for f in self.findings],
            'metadata': self.metadata,
            'analysis_time_ms': self.analysis_time_ms,
        }
