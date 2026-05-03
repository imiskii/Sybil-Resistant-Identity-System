"""
Package entrypoint for running simulations via `python -m simulations.network_simulation`.

Uses the runner module for CLI parsing and configuration file loading.
"""

from .runner import main

if __name__ == "__main__":
    raise SystemExit(main())
