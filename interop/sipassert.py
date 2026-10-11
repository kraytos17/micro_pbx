"""Structured assertions over sipp message logs and the PBX log.

sipp's `-trace_msg` logs are timestamped blocks of raw SIP with CRLF
line endings; multi-Via responses arrive comma-folded on one line.
Parsing once into SipMessage structs kills the whole grep/cut/sort/tr
pipeline class (which previously produced three separate bugs: stray
\\r breaking uniq, folded Via lines, head-truncated counts).
"""

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SipMessage:
    direction: str  # "received" | "sent" (from the logging endpoint's view)
    start_line: str
    headers: dict = field(default_factory=dict)  # lowercased name -> [values]

    def header(self, name):
        return self.headers.get(name.lower(), [])

    def is_request(self, method):
        return self.start_line.startswith(f"{method} ")

    def is_response(self, code):
        return self.start_line.startswith(f"SIP/2.0 {code}")


_BLOCK_SEP = re.compile(r"(?m)^-+\s+\d{4}-\d{2}-\d{2}T")
_DIRECTION = re.compile(r"UDP message (received|sent) \[(\d+)\] bytes:")


def parse_sipp_msg_log(path) -> list:
    """Parse a sipp -trace_msg log into structured SipMessage records."""
    text = Path(path).read_text(errors="replace").replace("\r\n", "\n")
    messages = []
    for chunk in _BLOCK_SEP.split(text):
        m = _DIRECTION.search(chunk)
        if not m:
            continue
        direction = m.group(1)
        body = chunk[m.end():].lstrip("\n")
        head, _, _ = body.partition("\n\n")
        lines = head.split("\n")
        if not lines or not lines[0]:
            continue
        # Unfold continuation lines (leading SP/HT) before splitting.
        unfolded = []
        for line in lines[1:]:
            if line[:1] in (" ", "\t") and unfolded:
                unfolded[-1] += " " + line.strip()
            elif ":" in line:
                unfolded.append(line)
        headers = {}
        for line in unfolded:
            name, _, value = line.partition(":")
            headers.setdefault(name.strip().lower(), []).append(value.strip())
        messages.append(SipMessage(direction, lines[0], headers))
    return messages


def via_branches(msg, host_port) -> list:
    """PBX Via branch values in a message, one per Via leg.

    Handles both wire forms: one Via line per hop and sipp's
    comma-folded single line (commas never occur inside a Via value).
    """
    branches = []
    for value in msg.header("via"):
        for leg in value.split(","):
            if host_port in leg:
                m = re.search(r"branch=([^;\s]+)", leg)
                if m:
                    branches.append(m.group(1))
    return branches


def assert_sipp_ok(out_txt):
    """Gate on sipp's Successful/Failed call counters, not its exit code.

    Exit codes lie: an abort-BYE after a matched 408 still exits 0.
    """
    lines = Path(out_txt).read_text(errors="replace").splitlines()
    ok = bad = None
    for line in lines:
        parts = line.split("|")
        if len(parts) < 3:
            continue
        if "Successful call" in parts[0]:
            ok = int(parts[2].strip())
        elif "Failed call" in parts[0]:
            bad = int(parts[2].strip())
    assert ok is not None, f"no Successful-call counter in {out_txt}"
    assert bad is not None, f"no Failed-call counter in {out_txt}"
    assert ok >= 1 and bad == 0, (
        f"sipp counters not green in {out_txt}: {ok} successful, {bad} failed")
