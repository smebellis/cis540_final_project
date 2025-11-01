import argparse
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pandas as pd


############################
# Heuristics for report_id
############################

def looks_like_hex_hash(s: str) -> bool:
    """
    Heuristic: pure MD5/SHA1/SHA256-looking hex blobs are not good 'report names'.
    """
    s_strip = s.strip().lower()
    if re.fullmatch(r"[0-9a-f]{32}", s_strip):
        return True  # MD5-ish
    if re.fullmatch(r"[0-9a-f]{40}", s_strip):
        return True  # SHA1-ish
    if re.fullmatch(r"[0-9a-f]{64}", s_strip):
        return True  # SHA256-ish
    return False


def looks_like_report_filename(s: str) -> bool:
    """
    True if s looks like a human-ish filename from a report or campaign,
    e.g. ghostnet.pdf, Aurora_Attacks.pdf, etc.
    """
    s_strip = s.strip()
    if re.search(r"\.(pdf|doc|docx|rtf|txt)$", s_strip, re.IGNORECASE):
        # avoid weird edge case "aaaaaaaaaaaaaaa.pdf" where it's still basically a hash
        basename = s_strip.rsplit(".", 1)[0]
        if not looks_like_hex_hash(basename):
            return True
    return False


def extract_candidate_names(event_elem):
    """
    From an <Event>, gather candidate human-readable labels:
      - <info> text
      - any <Attribute><item><value> where:
         * looks_like_report_filename(value), OR
         * (type in ["filename","comment"]) and value is not just a hash
    Return list of unique candidates in priority order.
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

        if not val:
            continue

        # obvious report/file names
        if looks_like_report_filename(val):
            candidates.append(val)
            continue

        # descriptive filename/comment types that aren't just hashes
        if typ in ["filename", "comment"]:
            if not looks_like_hex_hash(val):
                candidates.append(val)

    # de-dupe but preserve order
    seen = set()
    ordered = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            ordered.append(c)

    return ordered


def pick_best_report_id(candidates):
    """
    Pick a single canonical report_id for this event.
    Priority:
      1. first candidate that looks like a report filename (.pdf, .doc, etc)
      2. otherwise first candidate that isn't a pure hash
      3. otherwise None
    """
    for c in candidates:
        if looks_like_report_filename(c):
            return c

    for c in candidates:
        if not looks_like_hex_hash(c):
            return c

    return None


############################
# XML parsing
############################

def parse_single_event(event_elem, source_file):
    """
    Parse one <Event> element into many IOC rows (one row per Attribute item),
    and compute a report_id for the whole event.

    Returns list[dict] rows.
    """

    # Core event metadata
    event_id = (event_elem.findtext("id") or "").strip()
    event_date = (event_elem.findtext("date") or "").strip()
    event_info = (event_elem.findtext("info") or "").strip()

    # Derive report_id for this event
    candidates = extract_candidate_names(event_elem)
    report_id = pick_best_report_id(candidates) or ""

    rows = []

    attr_parent = event_elem.find("Attribute")
    if attr_parent is None:
        # still emit a row so we don't lose this event
        rows.append(
            {
                "source_file": source_file,
                "event_id": event_id,
                "event_date": event_date,
                "event_info": event_info,
                "report_id": report_id,
                "attr_id": None,
                "attr_category": None,
                "attr_type": None,
                "attr_value": None,
                "attr_comment": None,
            }
        )
        return rows

    for item in attr_parent.findall("item"):
        attr_id = (item.findtext("id") or "").strip()
        attr_category = (item.findtext("category") or "").strip()
        attr_type = (item.findtext("type") or "").strip()
        attr_value = (item.findtext("value") or "").strip()

        comment_node = item.find("comment")
        if comment_node is not None and comment_node.text:
            attr_comment = comment_node.text.strip()
        else:
            attr_comment = ""

        rows.append(
            {
                "source_file": source_file,
                "event_id": event_id,
                "event_date": event_date,
                "event_info": event_info,
                "report_id": report_id,
                "attr_id": attr_id,
                "attr_category": attr_category,
                "attr_type": attr_type,
                "attr_value": attr_value,
                "attr_comment": attr_comment,
            }
        )

    return rows


def parse_xml_file(xml_path: Path):
    """
    Parse every <Event> in a single XML file.
    """
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as e:
        raise RuntimeError(f"Failed to parse {xml_path}: {e}")

    root = tree.getroot()

    all_rows = []
    for event_elem in root.findall(".//Event"):
        all_rows.extend(parse_single_event(event_elem, source_file=xml_path.name))

    return all_rows


def load_all_xml(input_dir: Path):
    """
    Walk the directory, grab all *.xml files, parse each.
    Returns a pandas DataFrame of IOC rows with report_id included.
    """
    all_rows = []

    for xml_path in sorted(input_dir.glob("*.xml")):
        file_rows = parse_xml_file(xml_path)
        all_rows.extend(file_rows)

    columns = [
        "source_file",
        "event_id",
        "event_date",
        "event_info",
        "report_id",
        "attr_id",
        "attr_category",
        "attr_type",
        "attr_value",
        "attr_comment",
    ]

    if not all_rows:
        return pd.DataFrame(columns=columns)

    df = pd.DataFrame(all_rows)

    # Normalize whitespace, replace deprecated applymap
    for col in df.columns:
        if df[col].dtype == object:
            df[col] = df[col].apply(lambda x: x.strip() if isinstance(x, str) else x)

    # Drop duplicates
    df = df.drop_duplicates()

    # Deterministic sort
    df = df.sort_values(
        by=["event_date", "event_id", "report_id", "attr_type", "attr_value"],
        na_position="last",
    ).reset_index(drop=True)

    return df


############################
# Threat actor enrichment
############################

def load_apt_mapping(apt_map_path: Path | None):
    """
    Load the mapping CSV that ties campaign/report_id to an apt_group.
    Expected columns in CSV:
        report_id, apt_group

    If file missing or not provided, return empty DataFrame with those columns.
    """

    if apt_map_path is None:
        # user didn't provide --apt_map
        return pd.DataFrame(columns=["report_id", "apt_group"])

    if not apt_map_path.exists():
        print(f"[!] Warning: apt_map file not found at {apt_map_path}. Continuing with no attribution labels.")
        return pd.DataFrame(columns=["report_id", "apt_group"])

    apt_df = pd.read_csv(apt_map_path)

    # normalize string cols
    for col in ["report_id", "apt_group"]:
        if col in apt_df.columns:
            apt_df[col] = (
                apt_df[col]
                .fillna("")
                .astype(str)
                .str.strip()
            )

    # keep only the two columns we expect
    if "report_id" not in apt_df.columns:
        raise RuntimeError("apt_map.csv must have a 'report_id' column")
    if "apt_group" not in apt_df.columns:
        raise RuntimeError("apt_map.csv must have an 'apt_group' column")

    return apt_df[["report_id", "apt_group"]]


def attach_apt_groups(df: pd.DataFrame, apt_df: pd.DataFrame):
    """
    Merge the IOC dataframe with the apt_map dataframe on 'report_id'.
    Adds df['apt_group'].
    """
    if apt_df is None or apt_df.empty:
        df["apt_group"] = ""
        return df

    merged = df.merge(apt_df, on="report_id", how="left")
    merged["apt_group"] = merged["apt_group"].fillna("").astype(str).str.strip()
    return merged


############################
# Output helpers
############################

def dataframe_to_jsonl(df: pd.DataFrame, jsonl_path: Path):
    """
    Write each row of df as a JSON object on its own line.
    """
    with jsonl_path.open("w", encoding="utf-8") as f:
        for _, row in df.iterrows():
            obj = row.to_dict()
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")


############################
# Instruction record builders
############################

def build_indicator_records(df: pd.DataFrame):
    """
    Instruction-style records for IOC extraction & grouping.
    Now includes report_id and apt_group if present.
    """
    records = []

    grouped = df.groupby(
        ["event_id", "event_date", "report_id", "apt_group"],
        dropna=False,
    )

    for (event_id, event_date, report_id, apt_group), g in grouped:
        # aggregate indicators grouped by attr_type
        ioc_by_type = {}
        for _, r in g.iterrows():
            t = r.get("attr_type", "") or "unknown"
            v = r.get("attr_value", "")
            if not v:
                continue
            ioc_by_type.setdefault(t, set()).add(v)

        # build user prompt
        apt_context = f"The campaign is attributed to {apt_group}. " if apt_group else ""
        rid_context = f"Report ID: {report_id}. " if report_id else ""

        user_prompt = (
            f"{apt_context}{rid_context}"
            f"Event {event_id} on {event_date}. "
            "Extract all indicators (IPs, URLs, hashes, emails, etc.) grouped by type."
        )

        # build assistant answer
        answer_lines = []
        if apt_group:
            answer_lines.append(f"attributed_group: {apt_group}")
        if report_id:
            answer_lines.append(f"report_id: {report_id}")
        for t, vals in sorted(ioc_by_type.items()):
            answer_lines.append(f"{t}:")
            for v in sorted(vals):
                answer_lines.append(f"  - {v}")

        assistant_answer = "\n".join(answer_lines) if answer_lines else "No indicators found."

        records.append(
            {
                "input": user_prompt,
                "output": assistant_answer,
                "event_id": event_id,
                "event_date": event_date,
                "report_id": report_id,
                "apt_group": apt_group,
            }
        )

    return pd.DataFrame(records)


def build_attribution_records(df: pd.DataFrame):
    """
    Instruction-style records for attribution / actor reasoning.
    'Given these IOCs, who is responsible and why?'
    """
    records = []

    grouped = df.groupby(
        ["event_id", "event_date", "report_id", "apt_group"],
        dropna=False,
    )

    for (event_id, event_date, report_id, apt_group), g in grouped:
        # gather IOCs into a readable block
        indicators = []
        for _, r in g.iterrows():
            val = r.get("attr_value", "")
            t = r.get("attr_type", "")
            if val:
                indicators.append(f"{t}: {val}")

        ioc_block = "\n".join(sorted(set(indicators))) if indicators else "(no indicators captured)"

        # user prompt
        user_prompt_lines = [
            f"Event {event_id} observed on {event_date}.",
            f"Report ID: {report_id}" if report_id else "Report ID: (unknown)",
            "",
            "Indicators:",
            ioc_block,
            "",
            "Which threat actor / APT group is this activity most commonly attributed to, and why?",
        ]
        user_prompt = "\n".join(user_prompt_lines).strip()

        # assistant answer
        if apt_group:
            assistant_answer = (
                f"The activity is attributed to {apt_group}.\n\n"
                "This attribution is based on overlap in infrastructure, tooling, "
                "and prior reporting that links these indicators to that group."
            )
        else:
            assistant_answer = (
                "Attribution is unclear. There is no mapped APT group for this event. "
                "These indicators alone are insufficient to confidently assign a threat actor."
            )

        records.append(
            {
                "input": user_prompt,
                "output": assistant_answer,
                "event_id": event_id,
                "event_date": event_date,
                "report_id": report_id,
                "apt_group": apt_group,
            }
        )

    return pd.DataFrame(records)


############################
# main()
############################

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Build fine-tuning friendly CTI dataset from XML dumps.\n"
            "- Parses events and IOCs\n"
            "- Derives a human-readable report_id per event\n"
            "- Joins an APT/actor mapping on report_id\n"
            "- Emits flat tables and instruction datasets"
        )
    )
    parser.add_argument(
        "--input_dir",
        type=str,
        required=True,
        help="Folder containing one or more .xml files",
    )
    parser.add_argument(
        "--apt_map",
        type=str,
        default=None,
        help="CSV mapping file with columns: report_id,apt_group",
    )
    parser.add_argument(
        "--out_csv",
        type=str,
        default="combined.csv",
        help="Path to write the flat IOC table as CSV",
    )
    parser.add_argument(
        "--out_jsonl",
        type=str,
        default="combined.jsonl",
        help="Path to write the flat IOC table as JSONL",
    )
    parser.add_argument(
        "--out_instruct_ioc",
        type=str,
        default="instruct_ioc.jsonl",
        help="Path to write IOC extraction instruction records as JSONL",
    )
    parser.add_argument(
        "--out_instruct_attrib",
        type=str,
        default="instruct_attribution.jsonl",
        help="Path to write attribution instruction records as JSONL",
    )

    args = parser.parse_args()

    input_dir = Path(args.input_dir).expanduser().resolve()
    apt_map_path = Path(args.apt_map).expanduser().resolve() if args.apt_map else None

    # 1. Parse XMLs -> IOC dataframe (with report_id)
    df = load_all_xml(input_dir)

    # 2. Load APT mapping (report_id -> apt_group) and merge
    apt_df = load_apt_mapping(apt_map_path)
    df = attach_apt_groups(df, apt_df)

    # 3. Write combined IOC table
    csv_path = Path(args.out_csv).expanduser().resolve()
    jsonl_path = Path(args.out_jsonl).expanduser().resolve()
    df.to_csv(csv_path, index=False)
    dataframe_to_jsonl(df, jsonl_path)

    print(f"[+] Wrote flat table CSV -> {csv_path}")
    print(f"[+] Wrote flat table JSONL -> {jsonl_path}")
    print(f"[+] Total IOC rows: {len(df)}")

    # 4. Build instruction sets
    ioc_df = build_indicator_records(df)
    attrib_df = build_attribution_records(df)

    ioc_jsonl_path = Path(args.out_instruct_ioc).expanduser().resolve()
    attrib_jsonl_path = Path(args.out_instruct_attrib).expanduser().resolve()
    dataframe_to_jsonl(ioc_df, ioc_jsonl_path)
    dataframe_to_jsonl(attrib_df, attrib_jsonl_path)

    print(f"[+] Wrote IOC instruction JSONL -> {ioc_jsonl_path}")
    print(f"[+] Total IOC instruction records: {len(ioc_df)}")

    print(f"[+] Wrote Attribution instruction JSONL -> {attrib_jsonl_path}")
    print(f"[+] Total Attribution instruction records: {len(attrib_df)}")


if __name__ == "__main__":
    main()
