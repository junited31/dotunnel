"""`python -m dotunnel` is the same entry point as the `dotunnel` command."""

from .operator import main

if __name__ == "__main__":
    raise SystemExit(main())
