import copy

import pytest
import yaml
from fastapi.testclient import TestClient

import main
from dlp.policy import DEFAULT_POLICY_PATH, PolicyError


def start_app():
    with TestClient(main.app):
        pass


def test_app_refuses_to_start_with_an_invalid_policy(db_engine, tmp_path, monkeypatch):
    with open(DEFAULT_POLICY_PATH, encoding="utf-8") as handle:
        document = copy.deepcopy(yaml.safe_load(handle))
    document["data_types"]["JWT"]["action"] = "explode"
    bad = tmp_path / "bad_policy.yaml"
    bad.write_text(yaml.safe_dump(document), encoding="utf-8")
    monkeypatch.setenv("DLP_POLICY_PATH", str(bad))

    with pytest.raises(PolicyError, match="unknown action"):
        start_app()


def test_app_refuses_to_start_with_a_missing_policy_file(db_engine, tmp_path, monkeypatch):
    monkeypatch.setenv("DLP_POLICY_PATH", str(tmp_path / "nope.yaml"))

    with pytest.raises(PolicyError, match="cannot read"):
        start_app()


def test_app_refuses_to_start_with_a_bad_llm_configuration(db_engine, monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai_compatible")
    monkeypatch.delenv("LLM_MODEL", raising=False)

    with pytest.raises(ValueError, match="LLM_MODEL"):
        start_app()


def test_importing_the_app_does_not_create_a_database_file():
    # conftest points DATABASE_URL at memory; the engine must not be a file
    assert main.engine.url.database in (None, "", ":memory:")


def test_a_custom_policy_file_is_used(session_factory, tmp_path, monkeypatch):
    with open(DEFAULT_POLICY_PATH, encoding="utf-8") as handle:
        document = copy.deepcopy(yaml.safe_load(handle))
    document["data_types"]["EMAIL"]["action"] = "block"
    custom = tmp_path / "strict.yaml"
    custom.write_text(yaml.safe_dump(document), encoding="utf-8")
    monkeypatch.setenv("DLP_POLICY_PATH", str(custom))

    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    main.app.dependency_overrides[main.get_db] = override_get_db
    try:
        with TestClient(main.app) as client:
            response = client.post("/inspect", json={"prompt": "mail dana@example.com"})
    finally:
        main.app.dependency_overrides.clear()

    assert response.status_code == 403
    assert response.json()["detail"]["data_types"] == ["EMAIL"]
