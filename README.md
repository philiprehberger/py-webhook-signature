# philiprehberger-webhook-signature

[![Tests](https://github.com/philiprehberger/py-webhook-signature/actions/workflows/publish.yml/badge.svg)](https://github.com/philiprehberger/py-webhook-signature/actions/workflows/publish.yml)
[![PyPI version](https://img.shields.io/pypi/v/philiprehberger-webhook-signature.svg)](https://pypi.org/project/philiprehberger-webhook-signature/)
[![GitHub release](https://img.shields.io/github/v/release/philiprehberger/py-webhook-signature)](https://github.com/philiprehberger/py-webhook-signature/releases)
[![Last updated](https://img.shields.io/github/last-commit/philiprehberger/py-webhook-signature)](https://github.com/philiprehberger/py-webhook-signature/commits/main)
[![License](https://img.shields.io/github/license/philiprehberger/py-webhook-signature)](LICENSE)
[![Bug Reports](https://img.shields.io/github/issues/philiprehberger/py-webhook-signature/bug)](https://github.com/philiprehberger/py-webhook-signature/issues?q=is%3Aissue+is%3Aopen+label%3Abug)
[![Feature Requests](https://img.shields.io/github/issues/philiprehberger/py-webhook-signature/enhancement)](https://github.com/philiprehberger/py-webhook-signature/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement)
[![Sponsor](https://img.shields.io/badge/sponsor-GitHub%20Sponsors-ec6cb9)](https://github.com/sponsors/philiprehberger)

HMAC-based webhook signature generation and verification with timing-safe comparison.

## Installation

```bash
pip install philiprehberger-webhook-signature
```

## Usage

### Signing a Payload

```python
from philiprehberger_webhook_signature import sign

signed = sign(payload='{"event": "order.created"}', secret="whsec_abc123")

print(signed.signature)   # HMAC hex digest
print(signed.timestamp)   # Unix timestamp
print(signed.to_header()) # "t=1234567890,sha256=abc..."
```

### Verifying a Signature

```python
from philiprehberger_webhook_signature import verify, parse_header

# Parse the signature header
header = request.headers["X-Webhook-Signature"]
signature, timestamp = parse_header(header)

# Verify (raises on failure)
verify(
    payload=request.body,
    secret="whsec_abc123",
    signature=signature,
    timestamp=timestamp,
    max_age=300.0,  # reject signatures older than 5 minutes
)
```

### Key Rotation

Use `verify_with_rotation` for zero-downtime secret rotation. It tries the current secret first and falls back to the previous secret if verification fails:

```python
from philiprehberger_webhook_signature import verify_with_rotation, parse_header

header = request.headers["X-Webhook-Signature"]
signature, timestamp = parse_header(header)

verify_with_rotation(
    payload=request.body,
    signature=signature,
    current_secret="whsec_new_secret",
    previous_secret="whsec_old_secret",  # optional fallback
    tolerance=300,
    timestamp=timestamp,
)
```

### Error Handling

```python
from philiprehberger_webhook_signature import (
    verify,
    SignatureError,
    SignatureExpiredError,
    SignatureMismatchError,
)

try:
    verify(payload, secret, signature, timestamp)
except SignatureExpiredError as e:
    print(f"Signature too old: {e.age}s > {e.max_age}s")
except SignatureMismatchError:
    print("Invalid signature")
except SignatureError as e:
    print(f"Verification failed: {e}")
```

### Custom Algorithm

```python
signed = sign(payload="data", secret="secret", algorithm="sha512")
verify(payload="data", secret="secret", signature=sig, timestamp=ts, algorithm="sha512")
```

### Disable Expiry Check

```python
verify(payload, secret, signature, timestamp, max_age=None)
```

## API

| Function / Class | Description |
|------------------|-------------|
| `sign(payload, secret, algorithm, timestamp)` | Generate an HMAC signature for a webhook payload |
| `verify(payload, secret, signature, timestamp, algorithm, max_age)` | Verify a webhook signature with timing-safe comparison |
| `verify_with_rotation(payload, signature, current_secret, previous_secret, tolerance, algorithm, timestamp)` | Verify with key rotation support (tries current then previous secret) |
| `parse_header(header, prefix)` | Parse a signature header string into (signature, timestamp) tuple |
| `SignedPayload` | Signed payload with `signature`, `timestamp`, `body`, and `to_header()` |
| `SignatureError` | Base exception for signature errors |
| `SignatureExpiredError` | Raised when signature age exceeds max_age |
| `SignatureMismatchError` | Raised when signature verification fails |

## Development

```bash
pip install -e .
python -m pytest tests/ -v
```

## Support

If you find this package useful, consider giving it a star on GitHub — it helps motivate continued maintenance and development.

[![LinkedIn](https://img.shields.io/badge/Philip%20Rehberger-LinkedIn-0A66C2?logo=linkedin)](https://www.linkedin.com/in/philiprehberger)
[![More packages](https://img.shields.io/badge/more-open%20source%20packages-blue)](https://philiprehberger.com/open-source-packages)

## License

[MIT](LICENSE)
