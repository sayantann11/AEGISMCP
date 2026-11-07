"""Local detectors for common PII and credentials.

Built-in rules are conservative pattern checks. Optional Presidio integration
adds context-aware recognizers and local NER for names and locations. No
automated detector can identify every sensitive fact in every language or
business context; callers should add organization-specific recognizers.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from typing import Any, Iterable, Mapping


@dataclass(frozen=True)
class Entity:
    kind: str
    value: str
    start: int
    end: int
    score: float = 1.0


@dataclass(frozen=True)
class _Rule:
    kind: str
    pattern: re.Pattern[str]
    group: str | int = 0
    validator: Any = None


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def _luhn_valid(value: str) -> bool:
    digits = _digits(value)
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    parity = len(digits) % 2
    for index, char in enumerate(digits):
        digit = int(char)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _iban_valid(value: str) -> bool:
    compact = re.sub(r"\s", "", value).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    remainder = 0
    for char in rearranged:
        digits = str(ord(char) - 55) if char.isalpha() else char
        for digit in digits:
            remainder = (remainder * 10 + int(digit)) % 97
    return remainder == 1


def _valid_ipv4(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def _valid_ipv6(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv6Address)
    except ValueError:
        return False


def _valid_pan(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Z]{5}\d{4}[A-Z]", value, re.I)
                and value[3].upper() in {"P", "C", "H", "F", "A", "T", "B", "L", "J", "G"})


_RULES: tuple[_Rule, ...] = (
    # Private keys and credentials embedded in URLs.
    _Rule("PRIVATE_KEY", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
        r"[\s\S]{20,}?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
        re.I)),
    _Rule("URL_CREDENTIAL", re.compile(
        r"(?i)(?:(?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://)"
        r"(?P<credential>[^\s/:@]+:[^\s/@]{1,128})(?=@)"), "credential"),
    # Secret-like provider formats. Keep patterns long enough to avoid common examples.
    _Rule("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    _Rule("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b")),
    _Rule("GITLAB_TOKEN", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    _Rule("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    _Rule("STRIPE_KEY", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    _Rule("GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    _Rule("API_KEY", re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}\b")),
    _Rule("JWT", re.compile(
        r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")),
    _Rule("BEARER_TOKEN", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"), 0),
    _Rule("BASIC_AUTH", re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/]{12,}={0,2}"), 0),
    # Labeled credentials, including JSON/YAML/env assignments. Only the value
    # is replaced so surrounding syntax remains usable to the model.
    _Rule("SECRET", re.compile(
        r"(?i)(?<![A-Z0-9])(?:api[_-]?(?:key|token)|access[_-]?token|refresh[_-]?token|"
        r"session[_-]?token|bearer[_-]?token|auth[_-]?(?:token|key)|token|secret|"
        r"client[_-]?secret|secret[_-]?key|aws[_-]?secret[_-]?access[_-]?key|"
        r"webhook[_-]?secret|signing[_-]?key|encryption[_-]?key|password|passwd|pwd|"
        r"private[_-]?key|credential|connection[_-]?string|database[_-]?url|redis[_-]?url|"
        r"authorization)(?![A-Z0-9])\s*[\"']?\s*[:=]\s*[\"']?(?P<value>[^\"'\s,;]+)"), "value"),
    # Financial identifiers.
    _Rule("CREDIT_CARD", re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"), 0, _luhn_valid),
    _Rule("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b", re.I), 0, _iban_valid),
    _Rule("UPI_ID", re.compile(
        r"(?i)\b[A-Z0-9._-]{2,}@(okaxis|okhdfcbank|oksbi|ybl|paytm|upi|ibl|axl|icici|sbi|axisbank)\b")),
    _Rule("UPI_ID", re.compile(r"(?i)\b(?:upi(?:\s+(?:id|handle))?)[\s:=]+(?P<value>[A-Z0-9._-]{2,}@[A-Z][A-Z0-9.-]{1,})"), "value"),
    _Rule("BANK_ACCOUNT", re.compile(
        r"(?i)\b(?:bank\s+)?account(?:\s+(?:number|no\.?))?\s*[:#=]?\s*"
        r"(?P<value>[A-Z0-9-]{8,34})\b"), "value"),
    _Rule("ROUTING_NUMBER", re.compile(
        r"(?i)\b(?:routing|ABA)\s*(?:number|no\.?|#)?\s*[:#=]?\s*(?P<value>\d{9})\b"), "value"),
    _Rule("OTP", re.compile(
        r"(?i)\b(?:one[- ]time\s+(?:password|passcode)|OTP|verification\s+code|security\s+code|PIN)"
        r"\s*[:#=]?\s*(?P<value>\d{4,8})\b"), "value"),
    # Government and identity numbers. Ambiguous numeric values require labels.
    _Rule("AADHAAR", re.compile(
        r"(?i)\b(?:aadhaar|aadhar|uid(?:ai)?)(?:\s*(?:number|no\.?|#))?\s*[:#=]?\s*"
        r"(?P<value>\d{4}[ -]?\d{4}[ -]?\d{4})\b"), "value"),
    _Rule("PAN", re.compile(r"(?i)\b[A-Z]{5}\d{4}[A-Z]\b"), 0, _valid_pan),
    _Rule("GSTIN", re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][A-Z0-9]Z[A-Z0-9]\b", re.I)),
    _Rule("US_SSN", re.compile(
        r"(?i)\b(?:SSN|social\s+security(?:\s+number)?)(?:\s*(?:number|no\.?|#))?\s*[:#=]?\s*"
        r"(?P<value>(?!000|666|9\d\d)\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4})\b"), "value"),
    _Rule("US_ITIN", re.compile(
        r"(?i)\b(?:ITIN|taxpayer\s+identification\s+number)\s*[:#=]?\s*"
        r"(?P<value>9\d{2}[- ]?[78]\d[- ]?\d{4})\b"), "value"),
    _Rule("PASSPORT", re.compile(
        r"(?i)\bpassport(?:\s+(?:number|no\.?|#))?\s*[:#=]?\s*"
        r"(?P<value>[A-Z0-9]{6,12})\b"), "value"),
    _Rule("DRIVER_LICENSE", re.compile(
        r"(?i)\b(?:driver'?s?\s+license|driving\s+license|DL)(?:\s+(?:number|no\.?|#))?"
        r"\s*[:#=]?\s*(?P<value>[A-Z0-9-]{5,20})\b"), "value"),
    _Rule("NATIONAL_ID", re.compile(
        r"(?i)\b(?:national\s+id|identity\s+card)(?:\s+(?:number|no\.?|#))?\s*[:#=]?\s*"
        r"(?P<value>[A-Z0-9-]{6,20})\b"), "value"),
    # Contact details and identifying context.
    _Rule("EMAIL", re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")),
    _Rule("PHONE", re.compile(
        r"(?i)\b(?:phone|mobile|telephone|tel|whatsapp|contact)(?:\s+(?:number|no\.?))?"
        r"\s*[:#=]?\s*(?P<value>\+?\d[\d ().-]{6,}\d)\b"), "value"),
    _Rule("PHONE", re.compile(r"(?<!\w)\+\d(?:[\d ().-]{6,}\d)(?!\w)")),
    _Rule("IP_ADDRESS", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), 0, _valid_ipv4),
    _Rule("IP_ADDRESS", re.compile(
        r"(?i)(?<![\w:])(?P<value>[A-F0-9:]{2,39})(?![\w:])"), "value", _valid_ipv6),
    _Rule("MAC_ADDRESS", re.compile(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b")),
    _Rule("DOB", re.compile(
        r"(?i)\b(?:date\s+of\s+birth|DOB|born(?:\s+on)?)(?:\s*[:=])?\s*"
        r"(?P<value>(?:\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/]\d{2,4}|"
        r"[A-Z][a-z]{2,8}\s+\d{1,2},?\s+\d{4}))\b"), "value"),
    _Rule("ADDRESS", re.compile(
        r"(?i)\b(?:home\s+)?address\s*[:=]\s*(?P<value>[^\n;]{8,160})"), "value"),
)


class PatternDetector:
    """Detect common secrets and PII using local rules plus optional Presidio.

    ``known_names`` provides exact names when they are known. Set
    ``presidio_analyzer`` to a local Presidio AnalyzerEngine to add NER and its
    broader recognizer registry. Presidio is intentionally optional so the
    base package stays lightweight and fully offline. ``custom_patterns`` maps
    organization-specific entity kinds to compiled or raw regular expressions.
    """

    def __init__(self, known_names: Iterable[str] = (), *,
                 presidio_analyzer: Any | None = None,
                 presidio_score_threshold: float = 0.5,
                 custom_patterns: Mapping[str, str | re.Pattern[str]] | None = None) -> None:
        names = sorted({name.strip() for name in known_names if name and name.strip()},
                       key=len, reverse=True)
        self._names = re.compile(
            r"(?<!\w)(?:" + "|".join(re.escape(name) for name in names) + r")(?!\w)", re.I
        ) if names else None
        self._presidio = presidio_analyzer
        self._presidio_threshold = presidio_score_threshold
        self._custom_patterns: list[tuple[str, re.Pattern[str]]] = []
        for kind, pattern in (custom_patterns or {}).items():
            normalized_kind = str(kind).upper()
            if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,47}", normalized_kind):
                raise ValueError(f"invalid custom entity kind: {kind!r}")
            self._custom_patterns.append((normalized_kind,
                                          re.compile(pattern) if isinstance(pattern, str) else pattern))

    @classmethod
    def with_presidio(cls, known_names: Iterable[str] = ()) -> "PatternDetector":
        """Build a local English Presidio analyzer; requires the ``pii`` extra
        and the ``en_core_web_sm`` spaCy model to have been installed locally.
        """
        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider
        except ImportError as exc:
            raise RuntimeError(
                "Presidio detection requires `pip install 'aegismcp[pii]'` and "
                "`python -m spacy download en_core_web_sm`"
            ) from exc
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        })
        analyzer = AnalyzerEngine(nlp_engine=provider.create_engine(), supported_languages=["en"])
        return cls(known_names, presidio_analyzer=analyzer)

    def detect(self, text: str) -> list[Entity]:
        matches: list[Entity] = []
        for rule in _RULES:
            for found in rule.pattern.finditer(text):
                start, end = found.span(rule.group)
                value = found.group(rule.group)
                if rule.validator is not None and not rule.validator(value):
                    continue
                matches.append(Entity(rule.kind, value, start, end))
        for kind, pattern in self._custom_patterns:
            for found in pattern.finditer(text):
                group = "value" if "value" in pattern.groupindex else 0
                start, end = found.span(group)
                matches.append(Entity(kind, found.group(group), start, end))
        if self._names:
            matches.extend(Entity("NAME", found.group(0), found.start(), found.end())
                           for found in self._names.finditer(text))
        if self._presidio is not None and text:
            # The proxy joins JSON string fields with NUL separators. Analyze
            # each field independently so NER cannot classify separator text
            # or produce spans that break the proxy's string boundaries.
            base_offset = 0
            for segment in text.split("\x00"):
                if segment:
                    for result in self._presidio.analyze(text=segment, language="en"):
                        if float(result.score) < self._presidio_threshold:
                            continue
                        kind = str(result.entity_type).upper()
                        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,47}", kind):
                            continue
                        local_start, local_end = int(result.start), int(result.end)
                        if 0 <= local_start < local_end <= len(segment):
                            start, end = base_offset + local_start, base_offset + local_end
                            matches.append(Entity(kind, text[start:end], start, end,
                                                  float(result.score)))
                base_offset += len(segment) + 1

        # Prefer the longest/highest-confidence span at each position. This
        # keeps specific identifiers (such as an IBAN) from becoming fragments.
        matches.sort(key=lambda entity: (entity.start, -(entity.end - entity.start), -entity.score))
        selected: list[Entity] = []
        for entity in matches:
            if selected and entity.start < selected[-1].end:
                continue
            selected.append(entity)
        return selected
