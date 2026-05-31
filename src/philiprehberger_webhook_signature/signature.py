from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass


class SignatureError(Exception):
    pass


class SignatureExpiredError(SignatureError):
    def __init__(self, age: float, max_age: float) -> None:
        self.age = age
        self.max_age = max_age
        super().__init__(f"Signature expired: age {age:.1f}s exceeds max {max_age:.1f}s")


class SignatureMismatchError(SignatureError):
    def __init__(self) -> None:
        super().__init__("Signature verification failed")


@dataclass
class SignedPayload:
    signature: str
    timestamp: int
    body: str

    def to_header(self, prefix: str = "sha256") -> str:
        return f"t={self.timestamp},{prefix}={self.signature}"


def sign(
    payload: str | bytes,
    secret: str | bytes,
    algorithm: str = "sha256",
    timestamp: int | None = None,
) -> SignedPayload:
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    if isinstance(secret, str):
        secret = secret.encode("utf-8")

    ts = timestamp if timestamp is not None else int(time.time())
    message = f"{ts}.{payload.decode('utf-8')}".encode("utf-8")

    hash_func = getattr(hashlib, algorithm, None)
    if hash_func is None:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    sig = hmac.new(secret, message, hash_func).hexdigest()

    return SignedPayload(signature=sig, timestamp=ts, body=payload.decode("utf-8"))


def verify(
    payload: str | bytes,
    secret: str | bytes,
    signature: str,
    timestamp: int,
    algorithm: str = "sha256",
    max_age: float | None = 300.0,
) -> bool:
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    if isinstance(secret, str):
        secret = secret.encode("utf-8")

    if max_age is not None:
        age = time.time() - timestamp
        if age > max_age:
            raise SignatureExpiredError(age, max_age)

    message = f"{timestamp}.{payload.decode('utf-8')}".encode("utf-8")

    hash_func = getattr(hashlib, algorithm, None)
    if hash_func is None:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    expected = hmac.new(secret, message, hash_func).hexdigest()

    if not hmac.compare_digest(signature, expected):
        raise SignatureMismatchError()

    return True


def verify_with_rotation(
    payload: str | bytes,
    signature: str,
    current_secret: str,
    previous_secret: str | None = None,
    tolerance: int = 300,
    algorithm: str = "sha256",
    timestamp: int | None = None,
) -> bool:
    """Verify a webhook signature with key rotation support.

    Try verifying with *current_secret* first. If that fails and
    *previous_secret* is provided, retry with the previous secret.
    This enables zero-downtime secret rotation.

    Args:
        payload: The raw webhook body.
        signature: The HMAC signature to verify.
        current_secret: The current signing secret.
        previous_secret: The previous signing secret (optional).
        tolerance: Maximum age in seconds for the timestamp check.
        algorithm: Hash algorithm name (default ``sha256``).
        timestamp: Unix timestamp from the webhook header.

    Returns:
        ``True`` if the signature is valid with either secret.

    Raises:
        SignatureExpiredError: If the signature is older than *tolerance*.
        SignatureMismatchError: If neither secret produces a matching signature.
    """
    if timestamp is None:
        raise SignatureError("timestamp is required for verification")

    max_age = float(tolerance) if tolerance else None

    try:
        return verify(
            payload=payload,
            secret=current_secret,
            signature=signature,
            timestamp=timestamp,
            algorithm=algorithm,
            max_age=max_age,
        )
    except SignatureMismatchError:
        if previous_secret is not None:
            return verify(
                payload=payload,
                secret=previous_secret,
                signature=signature,
                timestamp=timestamp,
                algorithm=algorithm,
                max_age=max_age,
            )
        raise


def sign_headers(
    payload: str | bytes,
    secret: str | bytes,
    *,
    header_name: str = "X-Webhook-Signature",
    algorithm: str = "sha256",
    timestamp: int | None = None,
) -> dict[str, str]:
    """Sign *payload* and return an HTTP-ready headers dict.

    Returns:
        Dict like {"X-Webhook-Signature": "t=1700000000,sha256=..."}.
    """
    signed = sign(payload, secret, algorithm=algorithm, timestamp=timestamp)
    return {header_name: signed.to_header(prefix=algorithm)}


def verify_header(
    payload: str | bytes,
    secret: str | bytes,
    header_value: str,
    *,
    algorithm: str = "sha256",
    max_age: float | None = 300.0,
) -> bool:
    """Parse a signature header and verify it in one call.

    Args:
        payload: The raw webhook body.
        secret: The signing secret.
        header_value: The full header value, e.g. ``"t=1700000000,sha256=..."``.
        algorithm: Hash algorithm name (must match the prefix in the header).
        max_age: Max signature age in seconds. Pass None to disable.

    Returns:
        True on success. Raises SignatureExpiredError or SignatureMismatchError on failure.
    """
    sig, ts = parse_header(header_value, prefix=algorithm)
    return verify(
        payload=payload,
        secret=secret,
        signature=sig,
        timestamp=ts,
        algorithm=algorithm,
        max_age=max_age,
    )


def parse_header(header: str, prefix: str = "sha256") -> tuple[str, int]:
    parts: dict[str, str] = {}
    for part in header.split(","):
        key, _, value = part.partition("=")
        parts[key.strip()] = value.strip()

    timestamp = int(parts.get("t", "0"))
    sig = parts.get(prefix, "")

    if not sig:
        raise SignatureError(f"No {prefix} signature found in header")

    return sig, timestamp
