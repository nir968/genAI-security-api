import pytest
import yaml

from mcp_proxy import cli
from mcp_proxy.cli import main
from mcp_proxy.pinning import PinStore
from mcp_proxy.policy import DEFAULT_PATH
from mcp_proxy.proxy import DEFAULT_PINS_PATH, ConfigError, config_from_env, upstream_environment
from mcp_proxy.policy import load_policy


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ("MCP_PROXY_TOKEN", "GATEWAY_URL", "MCP_PINS_PATH", "MCP_APPROVAL_POLL_SECONDS"):
        monkeypatch.delenv(name, raising=False)


# --- pins list / reset -----------------------------------------------------------------


@pytest.fixture
def pins(tmp_path):
    store = PinStore(tmp_path / "pins.json")
    store.record("corp-docs", "send_email", "a" * 64)
    store.record("corp-docs", "read_document", "b" * 64, "quarantined")
    store.record("other-server", "send_email", "c" * 64)
    return store


def test_pins_list_shows_every_entry(pins, capsys):
    assert main(["pins", "list", "--pins", str(pins.path)]) == 0
    out = capsys.readouterr().out.splitlines()
    assert len(out) == 3
    assert out[0].startswith("corp-docs  read_document  quarantined  " + "b" * 16)
    assert out[1].startswith("corp-docs  send_email  pinned  " + "a" * 16)


def test_pins_list_when_empty(tmp_path, capsys):
    assert main(["pins", "list", "--pins", str(tmp_path / "none.json")]) == 0
    assert "no pinned tools" in capsys.readouterr().out


def test_the_pin_file_can_come_from_the_environment(pins, monkeypatch, capsys):
    monkeypatch.setenv("MCP_PINS_PATH", str(pins.path))
    assert main(["pins", "list"]) == 0
    assert "send_email" in capsys.readouterr().out


def test_pins_reset_with_a_server_name(pins, capsys):
    assert main(["pins", "reset", "send_email", "--server", "corp-docs", "--pins", str(pins.path)]) == 0
    assert "reset" in capsys.readouterr().out
    assert pins.get("corp-docs", "send_email") is None
    assert pins.get("other-server", "send_email") is not None


def test_pins_reset_takes_the_server_from_the_policy(pins):
    assert main(["pins", "reset", "send_email", "--policy", str(DEFAULT_PATH), "--pins", str(pins.path)]) == 0
    assert pins.get("corp-docs", "send_email") is None


def test_pins_reset_finds_the_server_when_only_one_has_the_tool(pins):
    assert main(["pins", "reset", "read_document", "--pins", str(pins.path)]) == 0
    assert pins.get("corp-docs", "read_document") is None


def test_pins_reset_asks_which_server_when_it_is_ambiguous(pins, capsys):
    assert main(["pins", "reset", "send_email", "--pins", str(pins.path)]) == 2
    err = capsys.readouterr().err
    assert "say which server" in err and "corp-docs, other-server" in err
    assert pins.get("corp-docs", "send_email") is not None


def test_pins_reset_of_an_unknown_tool_without_a_server_asks_for_one(pins, capsys):
    assert main(["pins", "reset", "nothing", "--pins", str(pins.path)]) == 2
    assert "say which server" in capsys.readouterr().err


def test_pins_reset_of_a_tool_that_is_not_pinned(pins, capsys):
    assert main(["pins", "reset", "nothing", "--server", "corp-docs", "--pins", str(pins.path)]) == 1
    assert "is not pinned" in capsys.readouterr().err


def test_pins_commands_report_a_damaged_pin_file(tmp_path, capsys):
    path = tmp_path / "pins.json"
    path.write_text("garbage", encoding="utf-8")
    assert main(["pins", "list", "--pins", str(path)]) == 1
    assert "not valid JSON" in capsys.readouterr().err


def test_pins_reset_reports_a_bad_policy(pins, tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("server: 5", encoding="utf-8")
    assert main(["pins", "reset", "send_email", "--policy", str(bad), "--pins", str(pins.path)]) == 1
    assert "error:" in capsys.readouterr().err


def test_a_missing_pins_action_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["pins"])
    assert excinfo.value.code == 2


# --- running ---------------------------------------------------------------------------------


@pytest.fixture
def runner(monkeypatch):
    """Replace the real proxy with a stub that records its configuration."""
    seen = []

    async def fake_run_proxy(config):
        seen.append(config)

    monkeypatch.setattr(cli, "run_proxy", fake_run_proxy)
    return seen


def test_run_builds_the_config_and_starts_the_proxy(runner, monkeypatch, tmp_path):
    monkeypatch.setenv("MCP_PROXY_TOKEN", "t")
    monkeypatch.setenv("GATEWAY_URL", "http://gw:9")
    monkeypatch.setenv("MCP_PINS_PATH", str(tmp_path / "p.json"))
    assert main(["--policy", str(DEFAULT_PATH), "--", "python", "-m", "demo_server"]) == 0
    (config,) = runner
    assert config.upstream == ["python", "-m", "demo_server"]
    assert config.gateway_url == "http://gw:9" and config.token == "t"
    assert config.policy.server == "corp-docs" and config.pins_path == tmp_path / "p.json"


def test_run_uses_the_bundled_policy_by_default(runner, monkeypatch):
    monkeypatch.setenv("MCP_PROXY_TOKEN", "t")
    assert main(["--", "server"]) == 0
    assert runner[0].policy == load_policy()


def test_ctrl_c_is_a_clean_exit(monkeypatch):
    monkeypatch.setenv("MCP_PROXY_TOKEN", "t")

    async def interrupted(config):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "run_proxy", interrupted)
    assert main(["--", "server"]) == 0


def test_an_invalid_policy_refuses_to_start(runner, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("MCP_PROXY_TOKEN", "t")
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.safe_dump({"server": "s", "tools": {"t": {"scan_result": False}}}), encoding="utf-8")
    assert main(["--policy", str(bad), "--", "server"]) == 2
    err = capsys.readouterr().err
    assert "refusing to start" in err and "scan_result" in err
    assert runner == []


def test_a_missing_policy_file_refuses_to_start(runner, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("MCP_PROXY_TOKEN", "t")
    assert main(["--policy", str(tmp_path / "nope.yaml"), "--", "server"]) == 2
    assert "cannot read policy file" in capsys.readouterr().err


def test_a_missing_token_refuses_to_start(runner, capsys):
    assert main(["--", "server"]) == 2
    assert "MCP_PROXY_TOKEN is not set" in capsys.readouterr().err and runner == []


def test_a_missing_upstream_command_refuses_to_start(runner, monkeypatch, capsys):
    monkeypatch.setenv("MCP_PROXY_TOKEN", "t")
    assert main([]) == 2
    assert "no upstream command" in capsys.readouterr().err


def test_a_damaged_pin_file_refuses_to_start(runner, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("MCP_PROXY_TOKEN", "t")
    path = tmp_path / "pins.json"
    path.write_text("garbage", encoding="utf-8")
    monkeypatch.setenv("MCP_PINS_PATH", str(path))
    assert main(["--", "server"]) == 2
    assert "refusing to start" in capsys.readouterr().err and runner == []


def test_main_reads_sys_argv_by_default(runner, monkeypatch):
    monkeypatch.setenv("MCP_PROXY_TOKEN", "t")
    monkeypatch.setattr(cli.sys, "argv", ["mcp_proxy", "--", "server"])
    assert main() == 0


def test_stdout_is_left_alone_when_refusing_to_start(runner, capsys):
    main(["--", "server"])
    assert capsys.readouterr().out == ""  # stdout is the protocol channel


# --- configuration from the environment ---------------------------------------------------


def test_config_defaults(monkeypatch):
    config = config_from_env(load_policy(), ["python"], {"MCP_PROXY_TOKEN": "t"})
    assert config.gateway_url == "http://localhost:8000"
    assert config.pins_path == DEFAULT_PINS_PATH and DEFAULT_PINS_PATH.parts[-3:] == ("mcp_proxy", "state", "pins.json")
    assert config.poll_interval == 2.0


def test_config_from_a_given_environment():
    env = {"MCP_PROXY_TOKEN": "t", "GATEWAY_URL": "http://x:1", "MCP_PINS_PATH": "/tmp/p.json", "MCP_APPROVAL_POLL_SECONDS": "0.5"}
    config = config_from_env(load_policy(), ["a", "b"], env)
    assert (config.gateway_url, config.poll_interval, config.upstream) == ("http://x:1", 0.5, ["a", "b"])
    assert str(config.pins_path).replace("\\", "/") == "/tmp/p.json"


@pytest.mark.parametrize(
    "env, upstream, message",
    [
        ({}, ["x"], "MCP_PROXY_TOKEN"),
        ({"MCP_PROXY_TOKEN": ""}, ["x"], "MCP_PROXY_TOKEN"),
        ({"MCP_PROXY_TOKEN": "t"}, [], "no upstream"),
        ({"MCP_PROXY_TOKEN": "t", "MCP_APPROVAL_POLL_SECONDS": "soon"}, ["x"], "must be a number"),
        ({"MCP_PROXY_TOKEN": "t", "MCP_APPROVAL_POLL_SECONDS": "0"}, ["x"], "positive"),
        ({"MCP_PROXY_TOKEN": "t", "MCP_APPROVAL_POLL_SECONDS": "-1"}, ["x"], "positive"),
    ],
)
def test_bad_configuration_is_refused(env, upstream, message):
    with pytest.raises(ConfigError, match=message):
        config_from_env(load_policy(), upstream, env)


def test_the_upstream_server_does_not_get_the_proxys_token():
    env = upstream_environment({"MCP_PROXY_TOKEN": "t", "PATH": "/bin", "DEMO_RUG_PULL": "1", "GATEWAY_URL": "http://g"})
    assert env == {"PATH": "/bin", "DEMO_RUG_PULL": "1", "GATEWAY_URL": "http://g"}


def test_upstream_environment_reads_os_environ_by_default(monkeypatch):
    monkeypatch.setenv("MCP_PROXY_TOKEN", "t")
    monkeypatch.setenv("SOMETHING_ELSE", "1")
    env = upstream_environment()
    assert "MCP_PROXY_TOKEN" not in env and env["SOMETHING_ELSE"] == "1"
