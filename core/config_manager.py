"""
core/config_manager.py
Singleton configuration manager for BlueSentinel v2.0.
Loads all settings from .env, validates required keys, exposes Config object.
"""
import os
from pathlib import Path
from dotenv import load_dotenv
from dataclasses import dataclass, field
from typing import List, Optional


class ConfigurationError(Exception):
    pass


@dataclass
class Config:
    # AI Provider
    ai_provider: str = "openai"
    openai_api_key: str = ""
    openai_model: str = "gpt-4o"
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-5"

    # Threat Intelligence
    virustotal_api_keys: List[str] = field(default_factory=list)
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""
    shodan_api_key: str = ""
    misp_url: str = ""
    misp_key: str = ""

    # SIEM
    siem_host: str = ""
    siem_port: int = 514

    # Dashboard
    dashboard_port: int = 5000
    dashboard_username: str = "admin"
    dashboard_password: str = "changeme"

    # News feed (optional)
    news_api_key: Optional[str] = None

    # Derived
    base_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent)


_config_instance: Optional[Config] = None


def load_config(env_path: Optional[str] = None) -> Config:
    global _config_instance
    if _config_instance is not None:
        return _config_instance

    if env_path:
        env_file = Path(env_path)
    else:
        root = Path(__file__).parent.parent
        env_file = root / "config" / ".env"
        if not env_file.exists():
            env_file = root / ".env"
    if env_file.exists():
        load_dotenv(env_file)
    else:
        load_dotenv()

    provider = os.getenv("AI_PROVIDER", "openai").lower()
    if provider not in ("openai", "claude"):
        raise ConfigurationError(f"AI_PROVIDER must be 'openai' or 'claude', got: '{provider}'")

    vt_keys_raw = os.getenv("VIRUSTOTAL_API_KEYS", "")
    vt_keys = [k.strip() for k in vt_keys_raw.split(",") if k.strip()]

    _config_instance = Config(
        ai_provider=provider,
        openai_api_key=os.getenv("OPENAI_API_KEY", ""),
        openai_model=os.getenv("OPENAI_MODEL", "gpt-4o"),
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY", ""),
        anthropic_model=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5"),
        virustotal_api_keys=vt_keys,
        abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY", ""),
        otx_api_key=os.getenv("OTX_API_KEY", ""),
        shodan_api_key=os.getenv("SHODAN_API_KEY", ""),
        misp_url=os.getenv("MISP_URL", ""),
        misp_key=os.getenv("MISP_KEY", ""),
        siem_host=os.getenv("SIEM_HOST", ""),
        siem_port=int(os.getenv("SIEM_PORT", "514")),
        dashboard_port=int(os.getenv("DASHBOARD_PORT", "5000")),
        dashboard_username=os.getenv("DASHBOARD_USERNAME", "admin"),
        dashboard_password=os.getenv("DASHBOARD_PASSWORD", "changeme"),
        news_api_key=os.getenv("NEWS_API_KEY", "").strip() or None,
    )
    return _config_instance


def get_config() -> Config:
    if _config_instance is None:
        return load_config()
    return _config_instance
