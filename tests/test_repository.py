from phishing_guard.repository import Repository

def test_store_is_idempotent(tmp_path):
    repo = Repository(str(tmp_path / "test.sqlite3"))
    payload = {"content_sha256":"abc", "acquired_at":"2026-01-01T00:00:00+00:00",
               "message_id_header":"<x>", "subject":"hello"}
    first, inserted1 = repo.store_message(payload, "lab", "INBOX", "1", "42")
    second, inserted2 = repo.store_message(payload, "lab", "INBOX", "1", "42")
    assert first == second
    assert inserted1 is True
    assert inserted2 is False
