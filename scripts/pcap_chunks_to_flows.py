#!/usr/bin/env python3
"""
Convert CIC IDS pcap chunks to CSV flows using CICFlowMeter.
Reads from data/raw/cic_ids/pcap_chunks/<day>/ and writes to data/processed/cic_ids/flows/<day>/.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

# Paths relative to nal/
NAL_ROOT = Path(__file__).resolve().parent.parent
PCAP_CHUNKS = NAL_ROOT / "data" / "raw" / "cic_ids" / "pcap_chunks"
FLOWS_OUT = NAL_ROOT / "data" / "processed" / "cic_ids" / "flows"
CICFLOWMETER = NAL_ROOT / ".venv" / "bin" / "cicflowmeter"

DAYS = ("friday", "monday", "thursday", "tuesday", "wednesday")


def main() -> int:
    if not CICFLOWMETER.exists():
        print("CICFlowMeter not found. Create venv and install: python -m venv .venv && .venv/bin/pip install cicflowmeter", file=sys.stderr)
        return 1
    if not PCAP_CHUNKS.exists():
        print(f"Pcap chunks dir not found: {PCAP_CHUNKS}", file=sys.stderr)
        return 1

    FLOWS_OUT.mkdir(parents=True, exist_ok=True)

    for day in DAYS:
        inp = PCAP_CHUNKS / day
        out = FLOWS_OUT / day
        if not inp.exists() or not inp.is_dir():
            print(f"Skipping {day}: not found")
            continue
        pcap_count = sum(1 for f in inp.iterdir() if f.is_file())
        out.mkdir(parents=True, exist_ok=True)
        existing = len(list(out.glob("*.csv"))) if out.exists() else 0
        if existing >= pcap_count and pcap_count > 0:
            print(f"Skipping {day}: already has {existing} CSVs ({pcap_count} pcaps)")
            continue
        print(f"Processing {day} -> {out} ({pcap_count} files)")
        r = subprocess.run(
            [str(CICFLOWMETER), "-d", str(inp), "-c", str(out)],
            cwd=NAL_ROOT,
        )
        if r.returncode != 0:
            print(f"cicflowmeter failed for {day} with exit code {r.returncode}", file=sys.stderr)
            return r.returncode
    print("Done. CSVs saved under data/processed/cic_ids/flows/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
