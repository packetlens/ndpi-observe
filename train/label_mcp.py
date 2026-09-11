#!/usr/bin/env python3
"""
label_mcp.py — relabel SSE-pattern flows in a feature CSV as "MCP".

Usage:
    python3 train/label_mcp.py /tmp/features.csv /tmp/features_labeled.csv

MCP over SSE is identified by:
  - iat_max_s  > IAT_MAX_THRESHOLD   (server pushes are infrequent, seconds apart)
  - duration_s > DURATION_THRESHOLD  (persistent connection, not a one-shot request)
  - app in MCP_APPS                  (known MCP server domains)
  - proto == 6, dport == 443         (HTTPS/TLS only)
"""

import sys
import csv

IAT_MAX_THRESHOLD  = 2.0    # seconds between packets
DURATION_THRESHOLD = 5.0    # minimum flow lifetime
# TLS: Claude/Anthropic API SSE connections that nDPI can't identify (encrypted)
MCP_APPS = {"Claude", "Github", "Cloudflare", "ChatGPT", "Copilot", "TLS"}

def label_row(row):
    try:
        iat_max  = float(row["iat_max_s"])
        duration = float(row["duration_s"])
        proto    = float(row["proto"])
        dport    = float(row["dport"])
        app      = row["label"]
    except (KeyError, ValueError):
        return row

    if (proto == 6 and dport == 443
            and app in MCP_APPS
            and iat_max  > IAT_MAX_THRESHOLD
            and duration > DURATION_THRESHOLD):
        row = dict(row)
        row["label"] = "MCP"
    return row

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.csv> <output.csv>")
        sys.exit(1)

    in_path, out_path = sys.argv[1], sys.argv[2]
    mcp_count = 0
    total = 0

    with open(in_path, newline="") as fin, open(out_path, "w", newline="") as fout:
        reader = csv.DictReader(fin)
        writer = csv.DictWriter(fout, fieldnames=reader.fieldnames)
        writer.writeheader()
        for row in reader:
            total += 1
            labeled = label_row(row)
            if labeled["label"] == "MCP":
                mcp_count += 1
            writer.writerow(labeled)

    print(f"Total rows: {total}")
    print(f"Labeled as MCP: {mcp_count} ({100*mcp_count/total:.1f}%)")
    print(f"Output: {out_path}")

if __name__ == "__main__":
    main()
