import argparse
import re
import xml.etree.ElementTree as ET
from pathlib import Path
import pandas as pd


def looks_like_hex_hash(s: str) -> bool:
    """
    True if s is basically just a hex hash (32,40,64 chars of [0-9a-f]).
    We don't want to use pure hashes as campaign IDs.
    """
    s_strip = s.strip().lower()
    if re.fullmatch(r"[0-9a-f]{32}", s_strip):
        return True  # likely MD5
    if re.fullmatch(r"[0-9a-f]{40}", s_strip):
        return True  # likely SHA1
    if re.fullmatch(r"[0-9a-f]{64}", s_strip):
        return True  # likely SHA256
    return False


def looks_like_report_filename(s: str) -> bool:
    """
    True if s looks like a human-ish filename (PDF, doc, etc) rather than just a hash.
    """
    s_strip = s.strip()
    # check common report/doc extensions
    if re.search(r"\.(pdf|doc|docx|rtf|txt)$", s_strip, re.IGNORECASE):
        # reject pure hashes that just happen to end with .pdf (rare but let's be safe)
        if not looks_like_hex_hash(s_strip.split(".")[0]):
            return True
    return False


def extract_candidate_names(event_elem):
    """
    From an <Event>, gather all candidate 'report-ish' strings.
    We'll look at:
      - <info>
      - any <Attribute><item><value> where it looks like a report filename
      - any <Attribute><item><value> where type in ['filename','comment'] and not a pure hash
    Return a list of candidates (strings).
    """
    candidates = []

    info_text = event_elem.findtext("info")
    if info_text:
        info_text = info_text.strip()
        if info_text and not looks_like_hex_hash(info_text):
            candidates.append(info_text)

    for item in event_elem.findall("./Attribute/item"):
        val = item.findtext("value") or ""
        val = val.strip()
        typ = (item.findtext("type") or "").strip().lower()

        # skip empty
        if not val:
            continue

        # If it's clearly a report filename, take it
        if looks_like_report_filename(val):
            candidates.append(val)
            continue

        # If it's comment/filename type and not just a hash, also take it
        if typ in ["filename", "comment"]:
            if not looks_like_hex_hash(val):
                candidates.append(val)

    # de-dupe while preserving order
    seen = set()
    ordered = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            ordered.append(c)

    return ordered


def pick_best_report_id(candidates):
    """
    Given a list of candidate strings for one event, decide which to keep.
    Priority:
      1. first value that looks_like_report_filename(...)
      2. otherwise just the first non-hash string
      3. otherwise None
    """
    for c in candidates:
        if looks_like_report_filename(c):
            return c

    for c in candidates:
        if not looks_like_hex_hash(c):
            return c

    return None


def collect_all_report_ids(input_dir: Path):
    """
    Walk all *.xml files, parse each <Event>, pick a best report_id.
    Return a sorted unique list of report_id values (non-None).
    """
    report_ids = []

    for xml_path in sorted(input_dir.glob("*.xml")):
        try:
            tree = ET.parse(xml_path)
        except ET.ParseError as e:
            raise RuntimeError(f"Failed to parse {xml_path}: {e}")

        root = tree.getroot()
        for event_elem in root.findall(".//Event"):
            candidates = extract_candidate_names(event_elem)
            rid = pick_best_report_id(candidates)
            if rid:
                report_ids.append(rid)

    # stable unique list
    uniq = []
    seen = set()
    for rid in report_ids:
        if rid not in seen:
            seen.add(rid)
            uniq.append(rid)

    return sorted(uniq)


def main():
    parser = argparse.ArgumentParser(
        description="Generate apt_map.csv template using human-readable campaign/report IDs, "
                    "not raw hashes."
    )
    parser.add_argument(
        "--input_dir",
        required=True,
        help="Folder containing CTI XML files",
    )
    parser.add_argument(
        "--out_csv",
        default="apt_map.csv",
        help="Output CSV path (will contain columns: report_id,apt_group)",
    )

    args = parser.parse_args()

    input_dir = Path(args.input_dir).expanduser().resolve()
    out_csv = Path(args.out_csv).expanduser().resolve()

    report_ids = collect_all_report_ids(input_dir)

    df = pd.DataFrame(
        [{"report_id": rid, "apt_group": ""} for rid in report_ids],
        columns=["report_id", "apt_group"],
    )
    df.to_csv(out_csv, index=False)

    print(f"[+] Wrote {out_csv}")
    print(f"[+] Found {len(df)} candidate report_id values.")
    print("[!] Fill in apt_group in that CSV, then feed it to the main builder (we'll update that to join on report_id).")


if __name__ == "__main__":
    main()
