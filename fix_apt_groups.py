#!/usr/bin/env python
"""
Fix/normalize apt_group names in cti_apt_ioc_sft.jsonl and update instructions.

Usage:
    python fix_apt_groups.py \
        --input /path/to/cti_apt_ioc_sft.jsonl \
        --output /path/to/cti_apt_ioc_sft_aptfixed.jsonl
"""

import argparse
import json
import re
from pathlib import Path


# ------------- Heuristic mapping helpers -------------

# Direct substring -> canonical APT name mappings.
# Keys are lowercase substrings to search for in report_name or old apt_group.
CANONICAL_APT_SUBSTRINGS = {
    # Core number APTs
    "apt28": "APT28",
    "apt 28": "APT28",
    "apt29": "APT29",
    "apt 29": "APT29",
    "apt27": "APT27",
    "apt 27": "APT27",
    "apt10": "APT10",
    "apt 10": "APT10",

    # Synonyms / subgroups
    "sofacy": "APT28 (Sofacy)",
    "sednit": "APT28 (Sednit)",
    "zebrocy": "Zebrocy (APT28 subgroup)",
    "turla": "Turla",
    "epicturla": "Turla",
    "lazarus": "Lazarus Group",
    "andariel": "Andariel (Lazarus subgroup)",

    # Pandas
    "deep panda": "Deep Panda",
    "deeppanda": "Deep Panda",
    "emissary panda": "Emissary Panda",
    "putter panda": "Putter Panda",

    # Named campaign/actor Aggah
    "aggah": "Aggah",

    # You can keep adding here: "oceanlotus": "OceanLotus (APT32)", etc.
}


def infer_canonical_apt(report_name: str, old_apt_group: str) -> str:
    """
    Infer a canonical APT/group name from the report filename and the
    existing apt_group string using substring and regex heuristics.

    Falls back to the old_apt_group if nothing better is found.
    """
    rn = (report_name or "").lower()
    ag = (old_apt_group or "").lower()

    # 1. Check explicit substring mappings first
    for substr, canonical in CANONICAL_APT_SUBSTRINGS.items():
        if substr in rn or substr in ag:
            return canonical

    # 2. Generic APT## pattern (e.g., "APT28", "apt 28")
    m = re.search(r"\bapt\s*([0-9]{1,3})\b", rn, re.IGNORECASE)
    if m:
        return f"APT{m.group(1)}"
    m = re.search(r"\bapt\s*([0-9]{1,3})\b", ag, re.IGNORECASE)
    if m:
        return f"APT{m.group(1)}"

    # 3. If we see "lazarus" anywhere, call it Lazarus Group
    if "lazarus" in rn or "lazarus" in ag:
        return "Lazarus Group"

    # 4. Nothing matched: keep the existing apt_group as a "campaign name"
    #    (still useful for grouping, even if it's not a canonical actor name).
    return old_apt_group or report_name or "Unknown"


def process_file(input_path: Path, output_path: Path) -> None:
    """
    Read the input JSONL, normalize apt_group and instruction, write output JSONL.
    """
    num_total = 0
    num_changed = 0

    with input_path.open("r", encoding="utf-8") as fin, \
         output_path.open("w", encoding="utf-8") as fout:

        for line in fin:
            line = line.strip()
            if not line:
                continue

            num_total += 1
            rec = json.loads(line)

            old_group = rec.get("apt_group", "")
            report_name = rec.get("report_name", "")

            new_group = infer_canonical_apt(report_name, old_group)

            if new_group != old_group:
                num_changed += 1

            rec["apt_group"] = new_group
            rec["instruction"] = f"Give me all the IOCs for {new_group}."

            fout.write(json.dumps(rec) + "\n")

    print(f"[INFO] Processed {num_total} records.")
    print(f"[INFO] Updated apt_group for {num_changed} records.")
    print(f"[INFO] Output written to: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Normalize apt_group names and instructions in CTI IOC dataset."
    )
    parser.add_argument(
        "--input",
        type=str,
        required=True,
        help="Path to cti_apt_ioc_sft.jsonl",
    )
    parser.add_argument(
        "--output",
        type=str,
        required=True,
        help="Path to write cti_apt_ioc_sft_aptfixed.jsonl",
    )

    args = parser.parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    process_file(input_path, output_path)


if __name__ == "__main__":
    main()
