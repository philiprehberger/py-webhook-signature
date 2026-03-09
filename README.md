# philiprehberger-webhook-signature

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

## License

MIT
