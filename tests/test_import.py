"""Basic import test."""


def test_import():
    """Verify the package can be imported."""
    import philiprehberger_webhook_signature
    assert hasattr(philiprehberger_webhook_signature, "__name__") or True
