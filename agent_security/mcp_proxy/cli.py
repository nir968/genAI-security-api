"""Command line: run the proxy, or manage the tool pins.

    python -m mcp_proxy --policy policy.yaml -- python -m demo_server
    python -m mcp_proxy pins list
    python -m mcp_proxy pins reset send_email --policy policy.yaml

Everything the proxy prints goes to stderr: stdout belongs to the MCP protocol.
"""
import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path

from .pinning import PinStore, PinStoreError
from .policy import DEFAULT_PATH, PolicyError, load_policy
from .proxy import DEFAULT_PINS_PATH, ConfigError, config_from_env, run_proxy

EXIT_USAGE = 2


def _split_upstream(argv):
    """(arguments before "--", the upstream command after it)."""
    if "--" in argv:
        index = argv.index("--")
        return argv[:index], argv[index + 1:]
    return argv, []


def _pins_path(value):
    return Path(value or os.environ.get("MCP_PINS_PATH") or DEFAULT_PINS_PATH)


def _run_parser():
    parser = argparse.ArgumentParser(
        prog="python -m mcp_proxy",
        description="MCP security proxy: stdio server for the agent, stdio client for the real server.",
        epilog="Put the upstream command after '--'. Other commands: 'pins list', 'pins reset TOOL'.",
    )
    parser.add_argument("--policy", default=str(DEFAULT_PATH), help="policy file (default: the bundled policy.yaml)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser


def _pins_parser():
    # --pins may come before or after the action; SUPPRESS keeps a value given on
    # one side from being overwritten by the default on the other
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--pins",
        default=argparse.SUPPRESS,
        help="pin file (default: $MCP_PINS_PATH or the bundled state/pins.json)",
    )
    parser = argparse.ArgumentParser(
        prog="python -m mcp_proxy pins", description="Inspect or reset tool pins.", parents=[common]
    )
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("list", help="show every pinned or quarantined tool", parents=[common])
    reset = sub.add_parser("reset", help="forget a tool so it is trusted again on first use", parents=[common])
    reset.add_argument("tool")
    reset.add_argument("--server", help="server name (default: the 'server' of --policy)")
    reset.add_argument("--policy", help="policy file to take the server name from")
    return parser


def pins_command(argv) -> int:
    args = _pins_parser().parse_args(argv)
    store = PinStore(_pins_path(getattr(args, "pins", None)))
    try:
        if args.action == "list":
            entries = store.entries()
            if not entries:
                print("no pinned tools")
                return 0
            for server, tool, entry in entries:
                print(f"{server}  {tool}  {entry.get('status')}  {str(entry.get('sha256'))[:16]}  {entry.get('recorded_at')}")
            return 0

        server = args.server
        if not server and args.policy:
            server = load_policy(args.policy).server
        if not server:
            servers = sorted({s for s, tool, _ in store.entries() if tool == args.tool})
            if len(servers) == 1:
                server = servers[0]
            else:
                print(
                    "pins reset: say which server (--server NAME or --policy FILE)"
                    + (f"; {args.tool!r} is pinned for: {', '.join(servers)}" if servers else ""),
                    file=sys.stderr,
                )
                return EXIT_USAGE
        if store.reset(server, args.tool):
            print(f"{args.tool} on {server} reset: it will be trusted again on its next first use")
            return 0
        print(f"{args.tool} on {server} is not pinned", file=sys.stderr)
        return 1
    except (PinStoreError, PolicyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def run_command(argv) -> int:
    own, upstream = _split_upstream(argv)
    args = _run_parser().parse_args(own)
    logging.basicConfig(
        stream=sys.stderr,
        level=getattr(logging, args.log_level),
        format="%(asctime)s mcp-proxy %(levelname)s %(message)s",
    )
    try:
        policy = load_policy(args.policy)
        config = config_from_env(policy, upstream)
    except (PolicyError, ConfigError) as exc:
        print(f"mcp-proxy: refusing to start: {exc}", file=sys.stderr)
        return EXIT_USAGE
    try:
        PinStore(config.pins_path).entries()
    except PinStoreError as exc:
        print(f"mcp-proxy: refusing to start: {exc}", file=sys.stderr)
        return EXIT_USAGE
    try:
        asyncio.run(run_proxy(config))
    except KeyboardInterrupt:
        pass
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "pins":
        return pins_command(argv[1:])
    return run_command(argv)
