"""
sentra_web.py – Launch the Sentra web dashboard

Usage:
    python sentra_web.py [--port 7731] [--host 127.0.0.1] [--no-browser]

Security:
    Warns loudly if --host is set to a non-loopback address without TLS.
"""

import argparse
import os
import sys
import webbrowser
import threading
import time


def _parse_args():
    parser = argparse.ArgumentParser(
        description="Sentra Password Manager – Web Dashboard"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=7731, help="Port to listen on (default: 7731)")
    parser.add_argument("--no-browser", action="store_true", help="Don't open browser automatically")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload (dev mode)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--debug", action="store_true", help="Enable ultra-verbose debug mode")
    return parser.parse_args()


def _validate_host(host: str) -> None:
    """Ensure the host is strictly 127.0.0.1 to prevent external exposure."""
    if host != "127.0.0.1":
        print(
            f"!! ERROR: Invalid bind address '{host}'.\n"
            "   For security, Sentra Web API must explicitly bind to 127.0.0.1\n"
            "   to prevent unauthorized external access.\n",
            file=sys.stderr,
        )
        sys.exit(1)


def _open_browser(host: str, port: int) -> None:
    """Open the browser after a short delay to give uvicorn time to start."""
    def _delayed_open():
        time.sleep(1.5)
        url = f"http://{host}:{port}"
        print(f"\n>> Opening Sentra in your browser: {url}\n")
        webbrowser.open(url)

    t = threading.Thread(target=_delayed_open, daemon=True)
    t.start()


def main():
    args = _parse_args()

    _validate_host(args.host)

    # Set env vars consumed by the web.api modules
    os.environ.setdefault("SENTRA_ALLOWED_ORIGIN", f"http://{args.host}:{args.port}")

    print(
        f"\n[Sentra Password Manager – Web Dashboard]\n"
        f"   Server : http://{args.host}:{args.port}\n"
        f"   Mode   : {'development (auto-reload)' if args.reload else 'production'}\n"
        f"   Press Ctrl+C to stop.\n"
    )

    if not args.no_browser:
        _open_browser(args.host, args.port)

    try:
        import uvicorn
    except ImportError:
        print(
            "! uvicorn is not installed.\n"
            "    Run: pip install uvicorn[standard]\n",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.verbose or args.debug:
        os.environ["SENTRA_ULTRA_VERBOSE"] = "1"

    uvicorn.run(
        "web.api.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="debug" if (args.verbose or args.debug) else "info",
    )


if __name__ == "__main__":
    main()
