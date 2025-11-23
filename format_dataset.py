import json
from collections import defaultdict, Counter
from pathlib import Path

base = Path("/home/smebellis/cis540_final_project")

ioc_chat_path = base / "instruct_ioc_chat_fixed.jsonl"
out_path = base / "apt_ioc_chat.jsonl"

apt_counts = Counter()
total = 0
with open(ioc_chat_path, "r") as f:
    for line in f:
        total += 1
        obj = json.loads(line)
        ag = (obj.get("apt_group") or "").strip()
        if ag:
            apt_counts[ag] += 1

print("Total IOC-chat samples:", total)
print("APT counts:", apt_counts.most_common())

apt_to_ioc_snippets = defaultdict(list)

with open(ioc_chat_path, "r") as f:
    for line in f:
        obj = json.loads(line)
        apt = (obj.get("apt_group") or "").strip()
        if not apt:
            continue

        msgs = obj.get("messages", [])
        assistant_contents = [
            m["content"]
            for m in msgs
            if m.get("role") == "assistant" and m.get("content")
        ]
        if not assistant_contents:
            continue

        content = assistant_contents[0].strip()
        if content and content not in apt_to_ioc_snippets[apt]:
            apt_to_ioc_snippets[apt].append(content)

print("Number of APT groups:", len(apt_to_ioc_snippets))


system_prompt = (
    "You are a cyber threat intelligence assistant. "
    "Given the name of an APT group, you return a consolidated list of indicators of compromise (IOCs) "
    "that have been observed in historical reporting. Use a structured format with keys such as "
    "ip-src, ip-dst, url, domain, filename, md5, sha1, sha256, mutex, and others as appropriate."
)

num_examples = 0
with open(out_path, "w") as out_f:
    for apt, snippets in apt_to_ioc_snippets.items():
        if not snippets:
            continue

        combined = "\n\n".join(snippets)

        obj = {
            "messages": [
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": (
                        f"APT group: {apt}\n\n"
                        "List all known indicators of compromise (IOCs) associated with this group "
                        "based on historical reporting in a structured format."
                    ),
                },
                {"role": "assistant", "content": combined},
            ],
            "apt_group": apt,
            "task_type": "apt_to_ioc",
        }
        out_f.write(json.dumps(obj) + "\n")
        num_examples += 1

print("Number of APT->IOC examples written:", num_examples)
print("Output file:", out_path)
