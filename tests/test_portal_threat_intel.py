"""Tests for the threat-intelligence detection engine (Phase 1 B5)."""


class TestEvaluateExtension:
    def test_banned_extension_id(self):
        from app import threat_intel
        matches = threat_intel.evaluate_extension('ms-vscode.example-malware', 'ms-vscode', 'x')
        kinds = {m['indicator_type'] for m in matches}
        assert 'banned_extension' in kinds
        assert any(m['severity'] == 'critical' for m in matches)

    def test_malicious_publisher(self):
        from app import threat_intel
        matches = threat_intel.evaluate_extension('evilcorp.something', 'evilcorp', 'x')
        assert any(m['indicator_type'] == 'malicious_publisher' for m in matches)

    def test_publisher_derived_from_id_when_absent(self):
        from app import threat_intel
        matches = threat_intel.evaluate_extension('evilcorp.tool', publisher='', name='')
        assert any(m['indicator_type'] == 'malicious_publisher' for m in matches)

    def test_typosquat_near_miss_flagged(self):
        from app import threat_intel
        # one extra char vs the real ms-python.python
        matches = threat_intel.evaluate_extension('ms-python.pythonn', 'ms-python', 'Python')
        ts = [m for m in matches if m['indicator_type'] == 'typosquat']
        assert ts and ts[0]['severity'] == 'high'

    def test_legit_target_not_flagged(self):
        from app import threat_intel
        matches = threat_intel.evaluate_extension('ms-python.python', 'ms-python', 'Python')
        assert matches == []

    def test_unrelated_extension_clean(self):
        from app import threat_intel
        matches = threat_intel.evaluate_extension('acme.totally-unrelated-thing', 'acme', 'x')
        assert matches == []

    def test_feed_version_present(self):
        from app import threat_intel
        assert threat_intel.feed_version()
