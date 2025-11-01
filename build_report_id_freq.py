import argparse
import re
import xml.etree.ElementTree as ET
from pathlib import Path
import pandas as pd
from collections import Counter, defaultdict


########################################
# Heuristics to identify campaign/report names
########################################

HASH32 = re.compile(r"^[0-9a-fA-F]{32}$")   # MD5-ish
HASH40 = re.compile(r"^[0-9a-fA-F]{40}$")   # SHA1-ish
HASH64 = re.compile(r"^[0-9a-fA-F]{64}$")   # SHA256-ish

REPORT_EXT = re.compile(r"\.(pdf|doc|docx|rtf|txt|hwp)$", re.IGNORECASE)

def looks_like_hash(s: str) -> bool:
    s = s.strip()
    return bool(HASH32.fullmatch(s) or HASH40.fullmatch(s) or HASH64.fullmatch(s))

def looks_like_report_filename(s: str) -> bool:
    """
    Returns True if the string looks like a human-readable report or campaign filename
    instead of a bare hash.
    Ex: 'The_Sin_Digoo_Affair.pdf', 'wp_the-heartbeat-apt-campaign.pdf'
    """
    s = s.strip()
    if REPORT_EXT.search(s):
        # If the base (before extension) is literally just a hash, reject
        base = s.rsplit(".", 1)[0]
        if looks_like_hash(base):
            return False
        return True
    return False


########################################
# Extract a "report_id" from an <Event>
########################################

def extract_candidate_names(event_elem):
    """
    Collect candidate report/campaign names for an event.

    We look in:
    - <Event><info>
    - <Attribute><item><value> where:
        - value looks like a report filename (ending in .pdf etc)
        - OR item/@type is filename/comment and value is not just a hash

    We dedupe in order of appearance.
    """
    candidates = []

    # 1. <info>
    info_text = event_elem.findtext("info")
    if info_text:
        value = info_text.strip()
        if value and not looks_like_hash(value):
            candidates.append(value)

    # 2. Attribute items
    for item in event_elem.findall("./Attribute/item"):
        val = (item.findtext("value") or "").strip()
        typ = (item.findtext("type") or "").strip().lower()

        if not val:
            continue

        # Strong signal: looks like a human-written report filename
        if looks_like_report_filename(val):
            candidates.append(val)
            continue

        # Weak signal but still useful: descriptive comment/filename
        if typ in ["filename", "comment"]:
            if not looks_like_hash(val):
                candidates.append(val)

    # De-dupe while preserving order
    seen = set()
    ordered = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            ordered.append(c)

    return ordered


def pick_report_id(candidates):
    """
    Pick the best 'report_id' for the event:
    Priority:
    1. first thing that looks like a report filename (.pdf/.doc/etc)
    2. otherwise first non-hash string
    3. otherwise None
    """
    for c in candidates:
        if looks_like_report_filename(c):
            return c
    for c in candidates:
        if not looks_like_hash(c):
            return c
    return None


########################################
# Parse XML files in a directory
########################################

def extract_report_ids_from_xml(xml_path: Path):
    """
    Parse a single XML file and return list of report_ids (one per <Event> if present).
    """
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as e:
        print(f"[!] Failed to parse {xml_path}: {e}")
        return []

    root = tree.getroot()
    report_ids = []

    for event_elem in root.findall(".//Event"):
        candidates = extract_candidate_names(event_elem)
        rid = pick_report_id(candidates)
        if rid:
            report_ids.append(rid)

    return report_ids


def collect_report_ids(input_dir: Path):
    """
    Walk input_dir, parse each *.xml, gather report_ids.
    Returns:
    - counts: Counter(report_id -> frequency)
    """
    counts = Counter()

    for xml_path in sorted(input_dir.glob("*.xml")):
        rids = extract_report_ids_from_xml(xml_path)
        counts.update(rids)

    return counts


########################################
# Heuristic classification and APT mapping
########################################

def classify_report_id(report_id: str, freq: int) -> str:
    """
    Very rough heuristic:
    - If it contains certain known campaign markers or 'apt' or 'wp_' style,
      OR if it appears multiple times -> likely_public_campaign.
    - Otherwise -> generic_internal.
    """
    lowered = report_id.lower()

    indicator_keywords = [
        "apt",          # wp_apt28..., wp_apt1...
        "taidoor",
        "ixeshe",
        "luckycat",
        "sin_digoo",
        "heartbeat",
        "ghostnet",
        "lazarus",
        "menupass",
        "plead",
        "iron_tiger",
        "darkhotel",
        "naikon",
        "carbanak",
        "cobalt",
        "turla",
        "hafnium",
    ]

    if any(k in lowered for k in indicator_keywords):
        return "likely_public_campaign"
    if lowered.startswith("wp_"):
        return "likely_public_campaign"
    if freq >= 3:
        return "likely_public_campaign"
    return "generic_internal"


def build_static_apt_lookup():
    """
    Best-effort static mapping of known report_id patterns to APT groups.
    You can expand this over time.
    Keys are substrings to look for in the report_id (case-insensitive).
    Values are the APT / intrusion set label you want to teach.
    """
    return {
        "sin_digoo": "APT1 / Comment Crew",
        "ghostnet": "APT1 / Comment Crew",
        "apt1": "APT1 / Comment Crew",

        "heartbeat": "APT37 / Kimsuky / Reaper",  # NK cluster commonly called Reaper / Kimsuky

        "taidoor": "APT12 (Numbered Panda)",
        "ixeshe": "APT12 (Numbered Panda)",

        "luckycat": "APT17 / Luckycat cluster (PRC-linked)",
        "iron_tiger": "APT27 (Emissary Panda)",

        "menupass": "APT10 (MenuPass)",
        "apt10": "APT10 (MenuPass)",

        "plead": "BlackTech (PLEAD)",

        "darkhotel": "DarkHotel",
        "naikon": "Naikon (APT30-adjacent / PLA-linked)",
        "turla": "Turla (Snake / Venomous Bear)",
        "lazarus": "Lazarus Group",
        "carbanak": "FIN7 / Carbanak",
        "cobalt": "Cobalt Group / FIN7-adjacent",
        "hafnium": "HAFNIUM (PRC-linked)",
    }


def guess_apt_group(report_id: str, apt_lookup: dict) -> str:
    """
    Guess APT group from report_id by substring match.
    If we have no guess, return "".
    """
    lowered = report_id.lower()
    for key_substr, apt_name in apt_lookup.items():
        if key_substr in lowered:
            return apt_name
    return ""


########################################
# Main export routine
########################################

def build_report_id_frequency(input_dir: Path, out_csv: Path):
    # 1. Gather counts of report_ids
    counts = collect_report_ids(input_dir)

    # 2. Build rows with classification + apt guess
    apt_lookup = build_static_apt_lookup()

    rows = []
    for report_id, freq in counts.items():
        classification = classify_report_id(report_id, freq)
        apt_group_guess = guess_apt_group(report_id, apt_lookup)

        rows.append({
            "report_id": report_id,
            "frequency": freq,
            "classification": classification,
            "likely_apt_group": apt_group_guess,
            "notes": ""  # placeholder for you to fill later
        })

    # 3. Sort by frequency descending, then report_id
    rows = sorted(rows, key=lambda r: (-r["frequency"], r["report_id"].lower()))

    # 4. Write CSV
    df = pd.DataFrame(rows, columns=[
        "report_id",
        "frequency",
        "classification",
        "likely_apt_group",
        "notes",
    ])
    df.to_csv(out_csv, index=False)

    print(f"[+] Wrote {out_csv}")
    print(f"[+] Unique report_ids: {len(df)}")
    print("[!] classification='likely_public_campaign' usually means it's worth doing manual APT verification.")


########################################
# CLI
########################################

def main():
    parser = argparse.ArgumentParser(
        description="Analyze CTI XMLs to produce a frequency-ranked list of report_ids, "
                    "classify them, and guess likely APT groups."
    )
    parser.add_argument(
        "--input_dir",
        required=True,
        help="Directory containing CTI XML files (all *.xml will be scanned).",
    )
    parser.add_argument(
        "--out_csv",
        default="report_id_frequency.csv",
        help="Where to save the ranked report_id list with guesses.",
    )

    args = parser.parse_args()

    input_dir = Path(args.input_dir).expanduser().resolve()
    out_csv = Path(args.out_csv).expanduser().resolve()

    build_report_id_frequency(input_dir, out_csv)


if __name__ == "__main__":
    main()
