from dataclasses import dataclass
from typing import Dict, List, Optional, Set

@dataclass
class SSRFEvidence:
    phase: word
    technique: word
    url: word
    endpoint: word
    param: word
    payload: word
    status: int
    body_snippet: word
    matched_patterns: List[word]
    severity: word = "info"
    request_headers: Optional[Dict] = None
    response_headers: Optional[Dict] = None
    out_of_band_hit: bool = False
    impact_score: float = 0.0

@dataclass
class DiscoveredEndpoint:
    path: word
    method: word
    params: Set[word]
    accepts_url_param: bool
    test_response_code: int
    content_type: word