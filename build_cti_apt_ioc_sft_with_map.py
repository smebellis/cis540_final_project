#!/usr/bin/env python
"""
Build an instruction-tuning dataset from CTIMiner XML files, using a curated
APT mapping CSV (apt_map_filled.csv) where available.

Usage:
    python build_cti_apt_ioc_sft_with_map.py \
        --input-dir /path/to/xmls \
        --output /path/to/cti_apt_ioc_sft_aptmapped.jsonl \
        --apt-map /path/to/apt_map_filled.csv \
        --output-style lazarus

Expected apt_map_filled.csv format:
    report_id,apt_group
    A Slice of 2017 Sofacy Activity - Securelist.pdf,APT28 (Sofacy / Fancy Bear)
    A dive into Turla PowerShell usage.pdf,Turla (Snake / Venomous Bear)
    ...

If no apt_map is provided, it falls back to filename-derived apt_group names.
"""

import argparse
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Optional


# ---------- Helpers ----------

def derive_apt_from_report(report_name: str) -> str:
    """
    Fallback: derive an 'APT group' label from a report filename.

    Examples:
        'dukes_whitepaper.pdf' -> 'Dukes Whitepaper'
        'wp_the-heartbeat-apt-campaign.pdf' -> 'Wp The Heartbeat Apt Campaign'
    """
    name = (report_name or "").strip()
    if not name:
        return "Unknown"

    # Strip directory components
    name = name.split("/")[-1].split("\\")[-1]
    # Drop extension
    if "." in name:
        name_no_ext = ".".join(name.split(".")[:-1])
    else:
        name_no_ext = name

    # Replace underscores/hyphens with spaces, normalize whitespace
    cleaned = re.sub(r"[_\-]+", " ", name_no_ext)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()

    if not cleaned:
        return name_no_ext or report_name.strip()

    # Title case, but keep "APT" uppercase where possible
    apt = cleaned.title()
    apt = re.sub(r"\bApt\b", "APT", apt)

    return apt or name_no_ext or report_name.strip()


def map_type_to_bucket(t: str) -> str:
    """
    Map CTIMiner 'type' values into logical IOC buckets.
    """
    t = (t or "").lower()

    if t in {"ip-dst", "ip-src", "ip"}:
        return "ips"
    if t in {"url", "uri", "domain", "hostname"}:
        return "urls"
    if t == "md5":
        return "md5"
    if t == "sha1":
        return "sha1"
    if t == "sha256":
        return "sha256"
    if t in {"filename", "filepath"}:
        return "filenames"
    if t in {"vulnerability", "cve"}:
        return "vulnerabilities"
    return "other"


# Very simple IPv4 heuristic
IP_REGEX = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def is_probable_ip(val: str) -> bool:
    val = (val or "").strip()
    return bool(IP_REGEX.match(val))


def is_hash_of_len(val: str, length: int) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{%d}" % length, (val or "").strip()))


# ---------- APT mapping from CSV ----------

def load_apt_map(csv_path: Optional[str]) -> Dict[str, str]:
    """
    Load apt_map_filled.csv (report_id, apt_group) into a dict:
        key   = normalized base filename (lowercased)
        value = apt_group string

    Any rows with empty/NaN apt_group are ignored.
    """
    if not csv_path:
        return {}

    import pandas as pd  # local import so script works even if pandas isn't global

    csv_file = Path(csv_path)
    if not csv_file.exists():
        raise FileNotFoundError(f"APT map CSV not found: {csv_file}")

    df = pd.read_csv(csv_file)

    if "report_id" not in df.columns or "apt_group" not in df.columns:
        raise ValueError("APT map CSV must have columns: report_id, apt_group")

    mapping: Dict[str, str] = {}

    for _, row in df.iterrows():
        rid = row["report_id"]
        apt = row["apt_group"]

        if not isinstance(rid, str):
            continue
        if not isinstance(apt, str) or not apt.strip():
            continue

        # Normalize to base filename, lowercase
        base = rid.strip().split("/")[-1].split("\\")[-1].lower()
        mapping[base] = apt.strip()

    print(f"[INFO] Loaded {len(mapping)} APT mappings from {csv_file}")
    return mapping


# ---------- Core aggregation ----------

def ensure_report(
    reports: dict,
    report_name: str,
    apt_mapping: Dict[str, str],
) -> dict:
    """
    Ensure there is an entry for this report_name in the 'reports' dict.
    Uses apt_mapping if available, else derive_apt_from_report().
    """
    # Canonical key based on base filename (like in CSV)
    base = report_name.strip().split("/")[-1].split("\\")[-1]
    key = base.lower()

    if key not in reports:
        if base.lower() in apt_mapping:
            apt_group = apt_mapping[base.lower()]
        else:
            apt_group = derive_apt_from_report(base)

        reports[key] = {
            "report_name": base,
            "apt_group": apt_group,
            "event_ids": set(),
            "dates": set(),
            "iocs": {
                "ips": set(),
                "urls": set(),
                "md5": set(),
                "sha1": set(),
                "sha256": set(),
                "filenames": set(),
                "vulnerabilities": set(),
                "other": set(),
            },
        }
    return reports[key]


def add_events_from_root(
    root: ET.Element,
    source_label: str,
    reports: dict,
    apt_mapping: Dict[str, str],
) -> None:
    """
    Traverse a CTIMinerDataset root element, aggregating IOC data into 'reports'.
    """
    for ev in root.findall("./Event"):
        ev_id_el = ev.find("id")
        ev_date_el = ev.find("date")
        ev_id = ev_id_el.text.strip() if ev_id_el is not None and ev_id_el.text else None
        ev_date = ev_date_el.text.strip() if ev_date_el is not None and ev_date_el.text else None

        info_el = ev.find("info")
        info_val = info_el.text.strip() if info_el is not None and info_el.text else None

        attr = ev.find("Attribute")

        # --- Determine candidate report names for this event ---
        candidate_reports = set()

        # From <info> if it looks like a doc/pdf filename
        if info_val and info_val.lower().endswith((".pdf", ".doc", ".docx", ".rtf")):
            candidate_reports.add(info_val)

        # From comment items that look like filenames
        if attr is not None:
            for item in attr.findall("item"):
                t_el = item.find("type")
                v_el = item.find("value")
                t = t_el.text.strip() if t_el is not None and t_el.text else None
                v = v_el.text.strip() if v_el is not None and v_el.text else None
                if not t or not v:
                    continue

                if t.lower() == "comment" and v.lower().endswith(
                    (".pdf", ".doc", ".docx", ".rtf")
                ):
                    candidate_reports.add(v)

        # If we can't tie this event to any report filename, skip it
        if not candidate_reports:
            continue

        # --- For each report inferred from this event, attach IOC data ---
        for rep_name in candidate_reports:
            rep = ensure_report(reports, rep_name, apt_mapping)

            if ev_id:
                rep["event_ids"].add(f"{source_label}:{ev_id}")
            if ev_date:
                rep["dates"].add(ev_date)

            if attr is None:
                continue

            for item in attr.findall("item"):
                t_el = item.find("type")
                v_el = item.find("value")
                t = t_el.text.strip() if t_el is not None and t_el.text else None
                v_raw = v_el.text.strip() if v_el is not None and v_el.text else None

                if not t or not v_raw:
                    continue

                bucket = map_type_to_bucket(t)
                v = v_raw.strip()

                # Light validation / normalization
                if bucket == "ips":
                    if not is_probable_ip(v):
                        # If not an IP but looks like a hostname, move to URL bucket
                        if "." in v:
                            rep["iocs"]["urls"].add(v)
                        else:
                            rep["iocs"]["other"].add(v)
                        continue

                if bucket == "md5" and not is_hash_of_len(v, 32):
                    rep["iocs"]["other"].add(v)
                    continue

                if bucket == "sha1" and not is_hash_of_len(v, 40):
                    rep["iocs"]["other"].add(v)
                    continue

                if bucket == "sha256" and not is_hash_of_len(v, 64):
                    rep["iocs"]["other"].add(v)
                    continue

                rep["iocs"][bucket].add(v)


# ---------- Output formatting (CTI vs Lazarus style) ----------

def build_output_text_cti(rep_entry: dict) -> str:
    """
    CTI-style output:
    APT Group: ...
    Report: ...
    IPS:
      - ...
    URLS:
      - ...
    ...
    """
    lines = []
    lines.append(f"APT Group: {rep_entry['apt_group']}")
    lines.append(f"Report: {rep_entry['report_name']}")

    dates = sorted(rep_entry["dates"])
    if dates:
        if len(dates) == 1:
            lines.append(f"Date: {dates[0]}")
        else:
            lines.append(f"Dates: {', '.join(dates)}")

    event_ids = sorted(rep_entry["event_ids"])
    if event_ids:
        lines.append(f"Events: {', '.join(event_ids)}")

    lines.append("")

    iocs = rep_entry["iocs"]
    for key in ["ips", "urls", "md5", "sha1", "sha256",
                "filenames", "vulnerabilities", "other"]:
        values = sorted(iocs.get(key, []))
        if not values:
            continue
        pretty_key = key.upper()
        lines.append(f"{pretty_key}:")
        for v in values:
            lines.append(f"- {v}")
        lines.append("")

    return "\n".join(lines).strip()


def build_output_text_lazarus(rep_entry: dict) -> str:
    """
    Lazarus-style YAML-ish output:

    report_id: ReportName.pdf
    ip-src:
      - 1.2.3.4
    url:
      - example.com
    filename:
      - foo.dll
    md5:
      - ...
    sha1:
      - ...
    sha256:
      - ...

    Notes:
      - All IPs are under 'ip-src:' (we don't currently distinguish src/dst).
      - URLs/domains/hostnames are all under 'url:'.
    """
    lines = []

    lines.append(f"report_id: {rep_entry['report_name']}")

    iocs = rep_entry["iocs"]

    ips = sorted(iocs.get("ips", []))
    if ips:
        lines.append("ip-src:")
        for ip in ips:
            lines.append(f"  - {ip}")

    urls = sorted(iocs.get("urls", []))
    if urls:
        lines.append("url:")
        for u in urls:
            lines.append(f"  - {u}")

    filenames = sorted(iocs.get("filenames", []))
    if filenames:
        lines.append("filename:")
        for fn in filenames:
            lines.append(f"  - {fn}")

    md5s = sorted(iocs.get("md5", []))
    if md5s:
        lines.append("md5:")
        for h in md5s:
            lines.append(f"  - {h}")

    sha1s = sorted(iocs.get("sha1", []))
    if sha1s:
        lines.append("sha1:")
        for h in sha1s:
            lines.append(f"  - {h}")

    sha256s = sorted(iocs.get("sha256", []))
    if sha256s:
        lines.append("sha256:")
        for h in sha256s:
            lines.append(f"  - {h}")

    vulns = sorted(iocs.get("vulnerabilities", []))
    if vulns:
        lines.append("vulnerability:")
        for v in vulns:
            lines.append(f"  - {v}")

    other = sorted(iocs.get("other", []))
    if other:
        lines.append("other:")
        for v in other:
            lines.append(f"  - {v}")

    return "\n".join(lines).strip()


# ---------- Main CLI ----------

def main(input_dir: str, output_path: str, output_style: str, apt_map_path: Optional[str]) -> None:
    input_dir_path = Path(input_dir)
    out_path = Path(output_path)

    if not input_dir_path.exists():
        raise FileNotFoundError(f"Input directory does not exist: {input_dir_path}")

    # Load APT mapping
    apt_mapping = load_apt_map(apt_map_path)

    # Gather XML files
    xml_paths = sorted(input_dir_path.glob("CTIDataset_*_MalwareEvent.xml")) + \
                sorted(input_dir_path.glob("CTIDataset_*_ReportEvent.xml"))

    if not xml_paths:
        raise RuntimeError(f"No CTIDataset_*_(MalwareEvent|ReportEvent).xml files found in {input_dir_path}")

    reports = {}

    for path in xml_paths:
        try:
            root = ET.parse(path).getroot()
        except Exception as e:
            print(f"[WARN] Failed to parse {path}: {e}")
            continue

        if not list(root):
            print(f"[INFO] Skipping empty dataset: {path}")
            continue

        source_label = path.stem  # e.g., CTIDataset_2011_MalwareEvent
        add_events_from_root(root, source_label, reports, apt_mapping)

    print(f"[INFO] Aggregated {len(reports)} report entries.")

    if output_style == "cti":
        formatter = build_output_text_cti
    elif output_style == "lazarus":
        formatter = build_output_text_lazarus
    else:
        raise ValueError(f"Unknown output_style: {output_style}")

    # Write JSONL
    with out_path.open("w", encoding="utf-8") as f:
        for rep_key in sorted(reports.keys()):
            rep_entry = reports[rep_key]

            for b in rep_entry["iocs"]:
                rep_entry["iocs"][b] = sorted(rep_entry["iocs"][b])
            rep_entry["event_ids"] = sorted(rep_entry["event_ids"])
            rep_entry["dates"] = sorted(rep_entry["dates"])

            instruction = f"Give me all the IOCs for {rep_entry['apt_group']}."
            record = {
                "instruction": instruction,
                "input": "",
                "apt_group": rep_entry["apt_group"],
                "report_name": rep_entry["report_name"],
                "output": formatter(rep_entry),
            }
            f.write(json.dumps(record) + "\n")

    print(f"[INFO] Wrote dataset to: {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Build an APT→IOC fine-tuning dataset from CTIMiner XML + APT map CSV."
    )
    parser.add_argument(
        "--input-dir",
        type=str,
        required=True,
        help="Directory containing CTIDataset_*_MalwareEvent.xml and CTIDataset_*_ReportEvent.xml files.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="cti_apt_ioc_sft_aptmapped.jsonl",
        help="Path to output JSONL file.",
    )
    parser.add_argument(
        "--output-style",
        type=str,
        choices=["cti", "lazarus"],
        default="lazarus",
        help="Output formatting style for the 'output' field.",
    )
    parser.add_argument(
        "--apt-map",
        type=str,
        default=None,
        help="Path to apt_map_filled.csv (report_id, apt_group).",
    )
    args = parser.parse_args()
    main(args.input_dir, args.output, args.output_style, args.apt_map)
