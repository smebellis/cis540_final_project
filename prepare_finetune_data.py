import argparse
import json
import pandas as pd
from pathlib import Path
from collections import defaultdict, OrderedDict


def normalize_attr_type(t):
    """
    Make sure attribute types use stable, semantically meaningful keys.
    You can expand this mapping as you see patterns in your data.
    """
    t = t.strip().lower()

    # map vague types to cleaner keys
    if t in ["text", "timestamp", "time", "dt", "first-seen", "last-seen"]:
        return "timestamp_observed"
    if t in ["comment", "info", "report", "label"]:
        return "report_label"
    if t in ["filename", "file", "attachment"]:
        return "filename"

    # leave known CTI-ish types alone
    # md5, sha1, sha256, ip-src, ip-dst, url, domain, hostname, email-src, etc.
    return t


def group_iocs_for_event(event_df):
    """
    Given all rows for a single event_id, build the grouped IOC dict
    like:
    {
      "report_id": "The_Sin_Digoo_Affair.pdf",
      "md5": [...],
      "sha1": [...],
      "ip-src": [...],
      "timestamp_observed": [...],
      ...
    }

    Deduplicate values per type.
    """
    grouped = OrderedDict()

    # Assume these are consistent within the event
    report_id = event_df["report_id"].iloc[0]
    grouped["report_id"] = report_id

    # Collect values by normalized type
    buckets = defaultdict(list)
    for _, row in event_df.iterrows():
        raw_type = str(row["attr_type"]) if "attr_type" in row else ""
        value = str(row["attr_value"]) if "attr_value" in row else ""

        if not value or value == "nan":
            continue

        norm_type = normalize_attr_type(raw_type)

        # don't re-list the campaign doc name under generic "report_label" if it's identical to report_id
        if norm_type == "report_label" and value == report_id:
            continue

        if value not in buckets[norm_type]:
            buckets[norm_type].append(value)

    # Merge buckets in stable key order:
    # we'll surface hashes first, then network, then filenames, timestamps, etc.
    preferred_order = [
        "md5", "sha1", "sha256",
        "sha512", "ssdeep",
        "ip-src", "ip-dst", "domain", "hostname", "url", "email-src", "email-dst",
        "filename", "report_label", "timestamp_observed",
    ]

    # first: add any preferred keys that actually exist
    for key in preferred_order:
        if key in buckets:
            grouped[key] = buckets[key]

    # then: add any other leftover keys we didn't explicitly order
    for key in sorted(buckets.keys()):
        if key not in grouped:
            grouped[key] = buckets[key]

    return grouped


def build_ioc_extraction_sample(event_df):
    """
    Build the chat-style training example for IOC extraction.
    Returns a Python dict:
    {
      "messages": [
        {"role": "user", "content": "..."},
        {"role": "assistant", "content": "..."}
      ],
      "event_id": "...",
      "event_date": "...",
      "report_id": "...",
      "apt_group": "..."
    }
    """
    event_id = str(event_df["event_id"].iloc[0])
    event_date = str(event_df["event_date"].iloc[0]) if "event_date" in event_df else ""
    report_id = str(event_df["report_id"].iloc[0])
    apt_group = str(event_df["apt_group"].iloc[0]) if "apt_group" in event_df else ""

    # 1. Build the "observed values" list for the prompt
    observed_values = []
    for _, row in event_df.iterrows():
        raw_type = str(row["attr_type"]) if "attr_type" in row else ""
        norm_type = normalize_attr_type(raw_type)
        val = str(row["attr_value"]) if "attr_value" in row else ""
        if not val or val == "nan":
            continue
        observed_values.append(f"- {norm_type}: {val}")

    observed_block = "\n".join(sorted(set(observed_values)))

    # 2. Build the grouped IOC answer
    grouped = group_iocs_for_event(event_df)

    # turn that grouped dict into YAML-ish text
    # e.g.
    # report_id: The_Sin_Digoo_Affair.pdf
    # md5:
    #   - abc
    # sha1:
    #   - def
    def grouped_to_block(g):
        lines = []
        for k, vals in g.items():
            if isinstance(vals, list):
                lines.append(f"{k}:")
                for v in vals:
                    lines.append(f"  - {v}")
            else:
                # report_id is a string, not list
                lines.append(f"{k}: {vals}")
        return "\n".join(lines)

    answer_block = grouped_to_block(grouped)

    # 3. Build the user message
    # We explicitly instruct the model what we want, so behavior stays consistent.
    user_msg = (
        "You are a cyber threat intelligence assistant.\n"
        f"Event ID: {event_id}\n"
        f"Date Observed: {event_date}\n"
        f"Report ID: {report_id}\n"
        + (f"Associated Threat Actor (if known): {apt_group}\n" if apt_group else "") +
        "\n"
        "Observed values:\n"
        f"{observed_block}\n"
        "\n"
        "Task: Extract all malicious indicators (hashes, IPs, URLs, domains, filenames, "
        "timestamps, etc.) and group them by type using stable keys like md5, sha1, sha256, "
        "ip-src, url, filename, timestamp_observed. Respond ONLY with the structured block."
    )

    assistant_msg = answer_block

    sample = {
        "messages": [
            {"role": "user", "content": user_msg},
            {"role": "assistant", "content": assistant_msg},
        ],
        "event_id": event_id,
        "event_date": event_date,
        "report_id": report_id,
        "apt_group": apt_group,
        "task_type": "ioc_extraction"
    }

    return sample


def build_attribution_sample(event_df):
    """
    Build the chat-style attribution example for this event,
    but ONLY if we have a non-empty apt_group.

    We'll ask: "Which threat actor is most associated with this activity?"
    """
    apt_group = str(event_df["apt_group"].iloc[0]) if "apt_group" in event_df else ""
    if not apt_group or apt_group.lower() in ["nan", "none"]:
        return None  # skip if we don't know

    event_id = str(event_df["event_id"].iloc[0])
    event_date = str(event_df["event_date"].iloc[0]) if "event_date" in event_df else ""
    report_id = str(event_df["report_id"].iloc[0])

    # we'll summarize a subset of observables for context in the prompt
    # (hashes, IPs, domains are strongest signal)
    obs_lines = []
    for _, row in event_df.iterrows():
        t = normalize_attr_type(str(row.get("attr_type", "")))
        v = str(row.get("attr_value", ""))
        if not v or v == "nan":
            continue
        # emphasize classic attribution-y observables
        if t in ["md5", "sha1", "sha256", "ip-src", "ip-dst", "domain", "hostname", "url", "filename"]:
            obs_lines.append(f"- {t}: {v}")

    obs_block = "\n".join(sorted(set(obs_lines)))

    user_msg = (
        "Which threat actor is most associated with this activity?\n"
        f"Event ID: {event_id}\n"
        f"Date: {event_date}\n"
        f"Report ID: {report_id}\n"
        "Key observed indicators:\n"
        f"{obs_block}\n"
        "\n"
        "Answer with the most likely APT/group name and one-sentence rationale."
    )

    assistant_msg = (
        f"This activity is attributed to {apt_group}. "
        f"The indicators and TTPs in {report_id} have been publicly linked to this actor."
    )

    sample = {
        "messages": [
            {"role": "user", "content": user_msg},
            {"role": "assistant", "content": assistant_msg},
        ],
        "event_id": event_id,
        "event_date": event_date,
        "report_id": report_id,
        "apt_group": apt_group,
        "task_type": "attribution"
    }

    return sample


def main():
    parser = argparse.ArgumentParser(
        description="Generate chat-format fine-tuning data from combined2.csv"
    )
    parser.add_argument(
        "--in_csv",
        required=True,
        help="Path to combined2.csv (IOC rows with apt_group merged)."
    )
    parser.add_argument(
        "--out_ioc_jsonl",
        default="instruct_ioc_chat.jsonl",
        help="Where to write IOC extraction chat samples (JSONL)."
    )
    parser.add_argument(
        "--out_attr_jsonl",
        default="instruct_attribution_chat.jsonl",
        help="Where to write attribution chat samples (JSONL)."
    )

    args = parser.parse_args()

    in_path = Path(args.in_csv).resolve()
    out_ioc_path = Path(args.out_ioc_jsonl).resolve()
    out_attr_path = Path(args.out_attr_jsonl).resolve()

    df = pd.read_csv(in_path, dtype=str).fillna("")

    # We expect at least: event_id, report_id, apt_group, attr_type, attr_value
    needed_cols = ["event_id", "report_id", "attr_type", "attr_value"]
    for col in needed_cols:
        if col not in df.columns:
            raise RuntimeError(f"Missing required column in CSV: {col}")

    # Group by event_id
    ioc_samples = []
    attr_samples = []

    for event_id, event_df in df.groupby("event_id"):
        event_df = event_df.copy()

        # IOC extraction sample
        ioc_sample = build_ioc_extraction_sample(event_df)
        ioc_samples.append(ioc_sample)

        # Attribution sample (if apt_group present)
        attr_sample = build_attribution_sample(event_df)
        if attr_sample is not None:
            attr_samples.append(attr_sample)

    # Write IOC extraction samples to JSONL
    with out_ioc_path.open("w", encoding="utf-8") as f:
        for sample in ioc_samples:
            f.write(json.dumps(sample, ensure_ascii=False) + "\n")

    # Write attribution samples to JSONL
    with out_attr_path.open("w", encoding="utf-8") as f:
        for sample in attr_samples:
            f.write(json.dumps(sample, ensure_ascii=False) + "\n")

    print(f"[+] Wrote IOC extraction samples to {out_ioc_path} ({len(ioc_samples)} events)")
    print(f"[+] Wrote attribution samples to {out_attr_path} ({len(attr_samples)} events)")
    print("[!] Sanity check a few lines for formatting/PII before training.")


if __name__ == "__main__":
    main()
