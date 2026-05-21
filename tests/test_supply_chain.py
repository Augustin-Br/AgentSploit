from scanner.supply_chain import check_secrets


def test_supply_chain_skips_intentional_lab_fixtures_by_default() -> None:
    findings = check_secrets(include_lab_fixtures=False)
    paths = {finding.path for finding in findings}

    assert "database_creds.txt" not in paths
    assert "tests/test_fuzzer_detectors.py" not in paths


def test_supply_chain_can_include_lab_fixtures() -> None:
    findings = check_secrets(include_lab_fixtures=True)
    paths = {finding.path for finding in findings}

    assert "database_creds.txt" in paths
