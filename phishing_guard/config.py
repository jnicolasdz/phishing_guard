from dataclasses import dataclass
import os
from dotenv import load_dotenv

load_dotenv()

def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}

@dataclass(frozen=True)
class Settings:
    database_path: str = os.getenv("DATABASE_PATH", "./data/phishing_guard.sqlite3")
    ollama_base_url: str = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")
    llm_temperature: float = float(os.getenv("LLM_TEMPERATURE", "0"))
    imap_host: str = os.getenv("IMAP_HOST", "127.0.0.1")
    imap_port: int = int(os.getenv("IMAP_PORT", "993"))
    imap_username: str = os.getenv("IMAP_USERNAME", "")
    imap_password: str = os.getenv("IMAP_PASSWORD", "")
    imap_folder: str = os.getenv("IMAP_FOLDER", "INBOX")
    imap_quarantine_folder: str = os.getenv("IMAP_QUARANTINE_FOLDER", "Quarantine")
    imap_ssl: bool = _bool("IMAP_SSL", True)
    imap_validate_certs: bool = _bool("IMAP_VALIDATE_CERTS", True)
    imap_idle_timeout: int = int(os.getenv("IMAP_IDLE_TIMEOUT", "60"))
    imap_mark_seen_after_persistence: bool = _bool("IMAP_MARK_SEEN_AFTER_PERSISTENCE", True)
    auto_quarantine_enabled: bool = _bool("PHISHING_AUTO_QUARANTINE", False)
    risk_high: float = float(os.getenv("PHISHING_RISK_HIGH", "0.85"))
    risk_low: float = float(os.getenv("PHISHING_RISK_LOW", "0.30"))
    min_confidence: str = os.getenv("PHISHING_MIN_CONFIDENCE", "high")
    max_body_chars: int = int(os.getenv("MAX_BODY_CHARS", "12000"))

settings = Settings()
