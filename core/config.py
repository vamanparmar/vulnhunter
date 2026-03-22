"""
core/config.py
--------------
Configuration dataclass. Supports CLI args and YAML profile loading.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from pathlib import Path


@dataclass
class Config:
    """Central configuration. Populated from CLI or a YAML profile."""

    url: str
    module: str

    threads: int = 5
    timeout: int = 10
    proxy: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    delay: float = 0.0
    retries: int = 3
    rate_limit: int = 0

    wordlist: Optional[str] = None
    param: Optional[str] = None
    payload_encoding: str = "none"

    output: Optional[str] = None
    output_format: str = "json"
    verbose: bool = False
    dry_run: bool = False
    no_color: bool = False
    silent: bool = False

    follow_redirects: bool = True
    user_agent: Optional[str] = None
    profile: Optional[str] = None

    def proxy_dict(self) -> Optional[Dict[str, str]]:
        if self.proxy:
            return {"http": self.proxy, "https": self.proxy}
        return None

    def effective_user_agent(self) -> str:
        return self.user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )

    @classmethod
    def from_yaml(cls, path: str, overrides: Dict[str, Any] = None) -> "Config":
        """Load config from a YAML profile with optional CLI overrides."""
        try:
            import yaml
        except ImportError:
            raise ImportError("PyYAML required: pip install pyyaml")

        profile_path = Path(path)
        if not profile_path.exists():
            raise FileNotFoundError(f"Profile not found: {path}")

        with open(profile_path, "r") as f:
            data: Dict[str, Any] = yaml.safe_load(f) or {}

        if overrides:
            for k, v in overrides.items():
                if v is not None:
                    data[k] = v

        for required in ("url", "module"):
            if required not in data:
                raise ValueError(f"Profile missing required field: '{required}'")

        known = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)

    def to_dict(self) -> Dict[str, Any]:
        import dataclasses
        return dataclasses.asdict(self)
