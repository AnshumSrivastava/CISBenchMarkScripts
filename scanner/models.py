from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Any

@dataclass
class Finding:
    id: str
    title: str
    category: str
    severity: str        # HIGH, MEDIUM, LOW, INFO
    status: str          # PASS, FAIL, WARN, NOT_APPLICABLE
    description: str
    evidence: str
    expected: str
    remediation: str
    references: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SystemContext:
    platform: str
    distribution: str
    distribution_version: str
    distribution_id: str
    kernel: str
    hostname: str
    current_user: str
    is_root: bool
    init_system: str
    logging_mechanism: str
    available_tools: Dict[str, bool]
    auth_log_path: Optional[str] = None
    sshd_config_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
