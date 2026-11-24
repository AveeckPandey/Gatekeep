from handler import handler


def test_lambda_handler_initialization():
    # Verify handler is initialized and callable
    assert callable(handler)
    # Mangum handler wrapper checks
    assert hasattr(handler, "app")
    assert handler.app.title == "GateKeep API"
