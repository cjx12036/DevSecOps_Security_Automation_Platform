from .command_injection import detect_command_injection
from .insecure_deserialization import detect_insecure_deserialization
from .sql_injection import detect_sql_injection
from .ssrf import detect_ssrf
from .xss import detect_xss

__all__ = [
    "detect_command_injection",
    "detect_insecure_deserialization",
    "detect_sql_injection",
    "detect_ssrf",
    "detect_xss",
]
