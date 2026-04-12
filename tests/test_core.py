from home_monitor.core import normalize_device_name, summarize_status


def test_normalize_device_name_removes_unsafe_characters() -> None:
    assert normalize_device_name(" Front Door Cam #1 ") == "front-door-cam-1"


def test_normalize_device_name_rejects_empty_output() -> None:
    try:
        normalize_device_name("!!!")
        assert False, "Expected ValueError"
    except ValueError:
        assert True


def test_summarize_status_uses_normalized_device_name() -> None:
    assert summarize_status(" Living Room ", True) == {
        "device": "living-room",
        "status": "online",
    }
