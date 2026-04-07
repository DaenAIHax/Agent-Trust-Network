"""Colored terminal logging helpers."""

RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[36m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
GRAY   = "\033[90m"


def log(label: str, msg: str, color: str = RESET) -> None:
    """Print a labeled, colored log message."""
    print(f"{color}{BOLD}[{label}]{RESET} {msg}", flush=True)


def log_msg(direction: str, payload: dict) -> None:
    """Print a message payload with direction arrow."""
    import json
    text = payload.get("text") or json.dumps(payload, ensure_ascii=False)
    arrow = f"{GREEN}\u2192{RESET}" if direction == "OUT" else f"{YELLOW}\u2190{RESET}"
    print(f"  {arrow} {text}", flush=True)
