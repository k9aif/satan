# SPDX-License-Identifier: Apache-2.0
"""Command-line interface for K9X Satan — installed as the `k9x-satan` console script."""

import argparse
import os
import signal
import socket
import subprocess
import sys
import time
import webbrowser
from importlib.metadata import PackageNotFoundError, version as _pkg_version
from pathlib import Path

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 6660

STATE_DIR = Path.home() / ".k9x"
PID_FILE = STATE_DIR / "satan.pid"
LOG_FILE = STATE_DIR / "satan.log"


def _version() -> str:
    try:
        return _pkg_version("k9x-satan")
    except PackageNotFoundError:
        return "unknown"


def _display_host(host: str) -> str:
    return "localhost" if host in ("0.0.0.0", "::") else host


def _port_in_use(host: str, port: int) -> bool:
    probe_host = _display_host(host)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex((probe_host, port)) == 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="k9x-satan",
        description=(
            f"K9X Satan v{_version()} — adversarial red-team harness for K9-AIF.  "
            "https://satan.k9x.ai"
        ),
        epilog=(
            "Examples:\n"
            "  k9x-satan                 Start Satan (foreground)\n"
            "  k9x-satan --bg            Start Satan in the background\n"
            "  k9x-satan --stop          Stop a background instance\n"
            "  k9x-satan --port 9000     Use a different port (default: 6660)\n"
            "  k9x-satan --version       Show the installed k9x-satan version\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="store_true", help="show version and exit")
    parser.add_argument(
        "--host", default=os.environ.get("K9X_SATAN_HOST", DEFAULT_HOST),
        help=f"bind host (default: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--port", type=int, default=int(os.environ.get("K9X_SATAN_PORT", DEFAULT_PORT)),
        help=f"bind port (default: {DEFAULT_PORT}, env K9X_SATAN_PORT)",
    )
    parser.add_argument(
        "--no-browser", action="store_true",
        help="don't open a browser tab automatically",
    )
    parser.add_argument(
        "--bg", "--background", dest="bg", action="store_true",
        help="run in the background and return immediately",
    )
    parser.add_argument(
        "--stop", action="store_true",
        help="stop an instance previously started with --bg",
    )
    return parser


def _run_foreground(host: str, port: int, no_browser: bool) -> int:
    if _port_in_use(host, port):
        print(f"[k9x-satan] Port {port} is already in use — is k9x-satan already running?")
        print(f"[k9x-satan]   Try '--port <other-port>', or '--stop' if it was started with --bg.")
        return 1

    url = f"http://{_display_host(host)}:{port}"
    print("[k9x-satan] K9X Satan — Security Analysis Tool for Agentic Networks")
    print(f"[k9x-satan] Listening on {_display_host(host)}:{port}")
    print(f"[k9x-satan] URL: {url}")
    print("[k9x-satan] Press Ctrl+C to stop.")

    if not no_browser:
        import threading
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()

    import uvicorn
    import k9x_satan.app as satan_app
    uvicorn.run(satan_app.app, host=host, port=port, log_level="info")
    return 0


def _start_background(host: str, port: int, no_browser: bool) -> int:
    url = f"http://{_display_host(host)}:{port}"

    if _port_in_use(host, port):
        print(f"[k9x-satan] Already appears to be running at {url} "
              f"(port {port} is in use) — nothing to do.")
        return 0

    STATE_DIR.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable, "-m", "k9x_satan.cli",
        "--host", host, "--port", str(port), "--no-browser",
    ]
    with open(LOG_FILE, "ab") as log_f:
        proc = subprocess.Popen(
            cmd, stdout=log_f, stderr=log_f, stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    PID_FILE.write_text(str(proc.pid))

    print("[k9x-satan] K9X Satan — Security Analysis Tool for Agentic Networks")
    print(f"[k9x-satan] Listening on {_display_host(host)}:{port} (pid {proc.pid})")
    print(f"[k9x-satan] URL: {url}")
    print(f"[k9x-satan]   logs: {LOG_FILE}")
    print(f"[k9x-satan]   stop: k9x-satan --stop")

    if not no_browser:
        time.sleep(1.0)
        webbrowser.open(url)
    return 0


def _stop_background() -> int:
    if not PID_FILE.exists():
        print("[k9x-satan] No background k9x-satan process found.")
        return 0

    pid = int(PID_FILE.read_text().strip())
    try:
        os.kill(pid, signal.SIGTERM)
        print(f"[k9x-satan] Stopped (pid {pid}).")
    except ProcessLookupError:
        print(f"[k9x-satan] Process (pid {pid}) was not running.")
    finally:
        PID_FILE.unlink(missing_ok=True)
    return 0


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(f"k9x-satan {_version()}")
        return 0

    if args.stop:
        return _stop_background()
    if args.bg:
        return _start_background(args.host, args.port, args.no_browser)
    return _run_foreground(args.host, args.port, args.no_browser)


if __name__ == "__main__":
    raise SystemExit(main())
