from dataclasses import dataclass
from typing import Dict, List, Optional, Set


@dataclass
class SSRFEvidence:
    phase: str
    technique: str
    url: str
    endpoint: str
    param: str
    payload: str
    status: int
    body_snippet: str
    matched_patterns: List[str]
    severity: str = "info"
    request_headers: Optional[Dict] = None
    response_headers: Optional[Dict] = None
    out_of_band_hit: bool = False
    impact_score: float = 0.0


@dataclass
class DiscoveredEndpoint:
    path: str
    method: str
    params: Set[str]
    accepts_url_param: bool
    test_response_code: int
    content_type: str