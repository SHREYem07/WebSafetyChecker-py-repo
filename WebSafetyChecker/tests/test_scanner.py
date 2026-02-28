import FunctionCode as scanner


def test_normalize_target_url_adds_https_when_missing_scheme():
    assert scanner.normalize_target_url("example.com") == "https://example.com"


def test_normalize_target_url_keeps_existing_scheme():
    assert scanner.normalize_target_url("http://example.com") == "http://example.com"


def test_is_url_structurally_valid_accepts_http_https_only():
    assert scanner.is_url_structurally_valid("https://example.com") is True
    assert scanner.is_url_structurally_valid("http://example.com") is True
    assert scanner.is_url_structurally_valid("ftp://example.com") is False
    assert scanner.is_url_structurally_valid("example.com") is False


def test_max_severity_returns_highest_and_handles_empty():
    assert scanner.max_severity(["Low", "Medium", "High"]) == "High"
    assert scanner.max_severity([]) == "Low"


def test_score_to_severity_thresholds():
    assert scanner.score_to_severity(2) == "Low"
    assert scanner.score_to_severity(3) == "Medium"
    assert scanner.score_to_severity(6) == "High"


def test_normalize_verdict_label_maps_aliases():
    assert scanner.normalize_verdict_label("malicious") == "High Risk"
    assert scanner.normalize_verdict_label("guarded") == "Caution"
    assert scanner.normalize_verdict_label("benign") == "Safe"
    assert scanner.normalize_verdict_label("unknown-value") == ""


def test_build_sensitive_probe_paths_contains_generated_backup_paths_and_sorted_unique():
    paths = scanner.build_sensitive_probe_paths()

    assert "/.env" in paths
    assert "/.env.bak" in paths
    assert "/database.sql.gz" in paths
    assert paths == sorted(paths)
    assert len(paths) == len(set(paths))


def test_estimate_output_accuracy_high_when_checks_complete_and_transport_strong():
    result = {
        "ok": True,
        "status_code": 200,
        "ssl_fallback_used": False,
        "security": {"is_https": True},
        "phishing": {"level": "Low"},
        "app_risk": {"confidence_score": 90, "overall": "Low"},
        "active_probe": {"overall": "Low"},
        "sensitive_exposure": {"overall": "Low"},
        "tls": {"supported": True, "hostname_match": True, "self_signed": False, "tls_confidence": {"score": 95}},
        "domain_intel": {"severity": "Low"},
        "redirect_chain": {"severity": "Low"},
        "reputation_lookup": {"severity": "Low"},
    }

    accuracy = scanner.estimate_output_accuracy(result)

    assert accuracy["level"] == "High"
    assert accuracy["percentage"] >= 90
    assert accuracy["inputs"]["check_coverage"] == 100.0
    assert accuracy["adjustments"] == []


def test_estimate_output_accuracy_penalizes_insecure_and_failed_scan():
    result = {
        "ok": False,
        "status_code": 500,
        "ssl_fallback_used": True,
        "security": {"is_https": False},
        "phishing": {},
        "app_risk": {"confidence_score": 10, "overall": "Low"},
        "active_probe": {},
        "sensitive_exposure": {},
        "tls": {"supported": False, "hostname_match": False, "self_signed": False, "tls_confidence": {"score": 0}},
        "domain_intel": {},
        "redirect_chain": {},
        "reputation_lookup": {},
    }

    accuracy = scanner.estimate_output_accuracy(result)

    assert accuracy["level"] in {"Low", "Medium"}
    assert accuracy["percentage"] < 80
    assert "target is not HTTPS" in accuracy["adjustments"]
    assert "TLS details unavailable" in accuracy["adjustments"]
    assert "SSL verification was bypassed" in accuracy["adjustments"]
    assert "server returned 5xx response" in accuracy["adjustments"]
    assert "scan did not complete successfully" in accuracy["adjustments"]
