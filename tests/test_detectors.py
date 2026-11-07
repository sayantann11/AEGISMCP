from types import SimpleNamespace

import pytest

from aegismcp.detectors import PatternDetector
from aegismcp.engine import TokenizationEngine
from aegismcp.vault import InMemoryTokenVault


@pytest.mark.parametrize(("text", "kind", "value"), [
    ("OPENAI_API_KEY=sk-test-123456789012345678901234", "API_KEY",
     "sk-test-123456789012345678901234"),
    ("Authorization: Bearer abcdefghijklmnop123456", "BEARER_TOKEN",
     "Bearer abcdefghijklmnop123456"),
    ("Authorization: Basic ZmFrZTpzZWNyZXQ=", "BASIC_AUTH", "Basic ZmFrZTpzZWNyZXQ="),
    ("token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123456", "JWT",
     "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123456"),
    ("ghp_" + "A" * 40, "GITHUB_TOKEN", "ghp_" + "A" * 40),
    ("glpat-" + "A" * 24, "GITLAB_TOKEN", "glpat-" + "A" * 24),
    ("xoxb-1234567890-ABCDEF1234", "SLACK_TOKEN", "xoxb-1234567890-ABCDEF1234"),
    ("sk_live_" + "A" * 24, "STRIPE_KEY", "sk_live_" + "A" * 24),
    ("password='local-demo-secret'", "SECRET", "local-demo-secret"),
    ("AWS_SECRET_ACCESS_KEY=demo-aws-secret", "SECRET", "demo-aws-secret"),
    ("MY_CLIENT_SECRET=local-app-secret", "SECRET", "local-app-secret"),
    ("SERVICE_TOKEN=short", "SECRET", "short"),
    ("verification code: 123456", "OTP", "123456"),
    ("postgres://demo-user:demo-password@db.example.test/app", "URL_CREDENTIAL",
     "demo-user:demo-password"),
    ("4111 1111 1111 1111", "CREDIT_CARD", "4111 1111 1111 1111"),
    ("IBAN: GB82 WEST 1234 5698 7654 32", "IBAN", "GB82 WEST 1234 5698 7654 32"),
    ("Pay Ravi via ravi@okaxis", "UPI_ID", "ravi@okaxis"),
    ("Aadhaar: 2345-6789-0123", "AADHAAR", "2345-6789-0123"),
    ("PAN: ABCPD1234F", "PAN", "ABCPD1234F"),
    ("GSTIN 27ABCPD1234F1Z5", "GSTIN", "27ABCPD1234F1Z5"),
    ("SSN: 078-05-1120", "US_SSN", "078-05-1120"),
    ("ITIN: 912-70-1234", "US_ITIN", "912-70-1234"),
    ("Passport: X1234567", "PASSPORT", "X1234567"),
    ("Driver license: D1234567", "DRIVER_LICENSE", "D1234567"),
    ("Phone number: +1 (415) 555-2671", "PHONE", "+1 (415) 555-2671"),
    ("DOB: 1980-01-02", "DOB", "1980-01-02"),
    ("Address: 100 Main Street, Suite 4, London", "ADDRESS",
     "100 Main Street, Suite 4, London"),
    ("Server 192.168.1.42", "IP_ADDRESS", "192.168.1.42"),
    ("IPv6 2001:db8::1", "IP_ADDRESS", "2001:db8::1"),
    ("NIC 00:1A:2B:3C:4D:5E", "MAC_ADDRESS", "00:1A:2B:3C:4D:5E"),
])
def test_detects_common_sensitive_patterns(text, kind, value):
    entities = PatternDetector().detect(text)
    assert any(entity.kind == kind and entity.value == value for entity in entities)


def test_private_key_block_is_one_entity():
    block = "-----BEGIN PRIVATE KEY-----\n" + "fake-private-key-material-" * 2 + "\n-----END PRIVATE KEY-----"
    entities = PatternDetector().detect("key:\n" + block)
    assert [(entity.kind, entity.value) for entity in entities] == [("PRIVATE_KEY", block)]


@pytest.mark.parametrize("text", [
    "Order reference 1234567890",  # unlabeled number is not assumed to be a phone
    "Card-like number 4111 1111 1111 1112",  # invalid Luhn checksum
    "Bad address 999.999.999.999",  # invalid IPv4 octets
    "Ordinary email-looking support+test@example.org",  # email is sensitive and should be found
])
def test_expected_conservative_or_common_detection(text):
    entities = PatternDetector().detect(text)
    if text.startswith("Ordinary email"):
        assert [(entity.kind, entity.value) for entity in entities] == [
            ("EMAIL", "support+test@example.org")]
    else:
        assert entities == []


def test_named_person_matching_is_opt_in_and_case_insensitive():
    entities = PatternDetector(known_names=["Ada Lovelace"]).detect("Ask ADA LOVELACE to review")
    assert [(entity.kind, entity.value) for entity in entities] == [("NAME", "ADA LOVELACE")]


def test_organization_can_add_custom_identifier_pattern():
    detector = PatternDetector(custom_patterns={"EMPLOYEE_ID": r"\bEMP-\d{6}\b"})
    entities = detector.detect("Review record EMP-012345")
    assert [(entity.kind, entity.value) for entity in entities] == [
        ("EMPLOYEE_ID", "EMP-012345")]


def test_optional_presidio_results_are_normalized_and_thresholded():
    analyzer = SimpleNamespace(analyze=lambda **_: [
        SimpleNamespace(entity_type="PERSON", start=0, end=12, score=0.91),
        SimpleNamespace(entity_type="LOCATION", start=17, end=21, score=0.2),
    ])
    entities = PatternDetector(presidio_analyzer=analyzer).detect("Ada Lovelace in Rome")
    assert [(entity.kind, entity.value) for entity in entities] == [("PERSON", "Ada Lovelace")]


def test_optional_presidio_local_ner_detects_synthetic_person_and_location():
    spacy = pytest.importorskip("spacy")
    if not spacy.util.is_package("en_core_web_sm"):
        pytest.skip("install the optional en_core_web_sm model to exercise local NER")
    detector = PatternDetector.with_presidio()
    entities = detector.detect("user\x00Send the synthetic report to John Smith at 42 Example Road in London")
    assert any(entity.kind == "PERSON" and entity.value == "John Smith" for entity in entities)
    assert any(entity.kind == "LOCATION" and entity.value == "London" for entity in entities)
    assert all("\x00" not in entity.value and "AEGISMCP" not in entity.value for entity in entities)


def test_new_entity_kinds_tokenize_and_restore():
    engine = TokenizationEngine(PatternDetector(), InMemoryTokenVault())
    prompt = "Charge card 4111 1111 1111 1111 for account owner"
    tokenized = engine.tokenize(prompt, "session-sensitive-kinds")
    assert "4111 1111 1111 1111" not in tokenized.sanitized_text
    assert "[CREDIT_CARD_01]" in tokenized.sanitized_text
    restored = engine.restore("Payment method [CREDIT_CARD_01]", "session-sensitive-kinds")
    assert restored == "Payment method 4111 1111 1111 1111"
