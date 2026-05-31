"""Tests for sign_headers and verify_header one-call helpers."""

import pytest

from philiprehberger_webhook_signature import (
    SignatureMismatchError,
    parse_header,
    sign_headers,
    verify_header,
)


def test_sign_headers_default_name():
    headers = sign_headers("body", "secret")
    assert "X-Webhook-Signature" in headers
    sig, ts = parse_header(headers["X-Webhook-Signature"])
    assert sig
    assert ts > 0


def test_sign_headers_custom_name():
    headers = sign_headers("body", "secret", header_name="X-Stripe-Signature")
    assert "X-Stripe-Signature" in headers
    assert "X-Webhook-Signature" not in headers


def test_verify_header_success():
    payload = '{"event": "order.created"}'
    secret = "whsec_abc123"
    headers = sign_headers(payload, secret)
    assert verify_header(payload, secret, headers["X-Webhook-Signature"]) is True


def test_verify_header_tampered_payload():
    payload = '{"event": "order.created"}'
    secret = "whsec_abc123"
    headers = sign_headers(payload, secret)
    with pytest.raises(SignatureMismatchError):
        verify_header(
            '{"event": "order.deleted"}',
            secret,
            headers["X-Webhook-Signature"],
        )
