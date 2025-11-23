import json
from collections import defaultdict
import argparse

SYSTEM_PROMPT_APT = (
    "You are a cyber threat intelligence assistant. Given the name of an APT "
    "group, output all known indicators of compromise (IOCs) associated with that "
    "group based on historical reporting in a structured format including fields "
    "like report_id, ip-src, domain, filename, md5, sha1, sha256, mutex, and others "
    "as appropriate. Respond ONLY with the structured block."
)


def build_apt_ioc_dataset(input_path: str, output_path: str) -> None:
    """
    Convert an event-level IOC extraction dataset (instruct_ioc_qwen_clean-style)
    into an APT-level dataset: one sample per apt_group with all report IOCs
    aggregated for that APT.
    """

    # apt_group -> { report_id -> assistant_content }
    apt_reports = defaultdict(dict)

    with open(input_path, "r", encoding="utf-8") as fin:
        for line in fin:
            line = line.strip()
            if not line:
                continue

            obj = json.loads(line)
            apt_group = (obj.get("apt_group") or "").strip()
            if not apt_group:
                # skip events with unknown / unset APT
                continue

            report_id = obj.get("report_id")
            # assistant content is the structured IOC block (YAML-like)
            assistant_content = obj["messages"][2]["content"]

            # we keep one block per (APT, report_id); later we aggregate per APT
            apt_reports[apt_group][report_id] = assistant_content

    # Build one training example per APT
    examples = []
    for apt_group, reports in apt_reports.items():
        # Aggregate all report-level IOC blocks into one big structured block
        blocks = []
        for report_id, content in reports.items():
            blocks.append(content.strip())

        assistant_out = "\n\n".join(blocks)

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT_APT},
            {"role": "user", "content": f"APT group: {apt_group}"},
            {"role": "assistant", "content": assistant_out},
        ]

        examples.append(
            {
                "messages": messages,
                "apt_group": apt_group,
                "task_type": "apt_to_ioc",
            }
        )

    # Write as JSONL
    with open(output_path, "w", encoding="utf-8") as fout:
        for rec in examples:
            fout.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"Wrote {len(examples)} APT-level examples to {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Build APT→IOC Qwen training dataset from event-level IOC file."
    )
    parser.add_argument(
        "--input",
        type=str,
        default="instruct_ioc_qwen_clean.jsol",
        help="Path to the event-level JSONL/JSOL file.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="apt_ioc_chat.jsonl",
        help="Path to write the APT-level JSONL file.",
    )
    args = parser.parse_args()

    build_apt_ioc_dataset(args.input, args.output)
