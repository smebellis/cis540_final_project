import json
import argparse

# Canonical system prompt used for all samples
SYS_PROMPT = (
    "You are a cyber threat intelligence assistant. Given an event with observed "
    "values and metadata such as Event ID, Date Observed, Report ID, and an "
    "associated threat actor, extract all malicious indicators of compromise (IOCs) "
    "including hashes, IP addresses, URLs, domains, filenames, mutexes, email "
    "addresses, and other relevant artifacts. Return them in a structured block "
    "with fields like report_id, ip-src, ip-dst, domain, url, filename, md5, sha1, "
    "sha256, mutex, email-src, vulnerability, and timestamp_observed as "
    "appropriate. Respond ONLY with the structured block."
)

# Mapping learned automatically from entries where apt_group was already set
BASE_REPORT_TO_APT = {
    '556_10535_798405_Annex87_CyberAttacks.pdf': 'Lazarus Group',
    'The_Sin_Digoo_Affair.pdf': 'APT1 / Comment Crew',
    'wp_ixeshe.pdf': 'APT12 (Numbered Panda)',
    'wp_luckycat_redux.pdf': 'APT17 / Luckycat cluster (PRC-linked)',
    'wp_the-heartbeat-apt-campaign.pdf': 'APT37 / Kimsuky / Reaper',
    'Mandiant_APT1_Report.pdf': 'APT1 / Comment Crew',
    'RAP002_APT1_Technical_backstage.1.0.pdf': 'APT1 / Comment Crew',
    'circl-tr25-analysis-turla-pfinet-snake-uroburos.pdf': 'Turla (Snake / Venomous Bear)',
    'darkhotelappendixindicators_kl.pdf': 'DarkHotel',
    'darkhotel_kl_07.11.pdf': 'DarkHotel',
    'EpicTurla.pdf': 'Turla (Snake / Venomous Bear)',
    'KL_Epic_Turla_Technical_Appendix_20140806.pdf': 'Turla (Snake / Venomous Bear)',
    'Reuters_Turla.pdf': 'Turla (Snake / Venomous Bear)',
    'Turla_2_Penquin.pdf': 'Turla (Snake / Venomous Bear)',
    'Carbanak_APT_eng.pdf': 'FIN7 / Carbanak',
    'Darkhotel in 2015.pdf': 'DarkHotel',
    'SatelliteTurla(Securelist).pdf': 'Turla (Snake / Venomous Bear)',
    'The Naikon APT - Securelist.pdf': 'Naikon (APT30-adjacent / PLA-linked)',
    'ghostnet.pdf': 'APT1 / Comment Crew',
    'TheNaikonAPT-MsnMM2.pdf': 'Naikon (APT30-adjacent / PLA-linked)',
    'TheCitizenLab_Shifting-Tactics-Tracking-changes-in-years-long-...-campaign-against-Tibetans(Mar-10-16).pdf': 'FIN7 / Carbanak',
    'Trustwave_Carbanak _Anunak_Attack_Methodology(11-14-2016).pdf': 'FIN7 / Carbanak',
    'BAESystems_Lazarus-FalseFlag-Malware(02-20-2017).pdf': 'Lazarus Group',
    'BAESystems_Lazarus-Watering-hole-attacks(02-12-2017).pdf': 'Lazarus Group',
    'BAESytems_Taiwan-Heist-Lazarus-Tools-Ransomware(10-16-2017).pdf': 'Lazarus Group',
    'Kaspersky_Lazarus-Under-The-Hood-PDF_final(04-03-2017).pdf': 'Lazarus Group',
    'NCSC_Turla-Neuron-Nautilus-Snake-malware_1(11-22-2017).pdf': 'Turla (Snake / Venomous Bear)',
    'RSA_the-carbanak-fin7-syndicate(11-22-2017).pdf': 'FIN7 / Carbanak',
    'RSA_the-shadows-of-ghosts-carbanak-report(11-30-2017).pdf': 'FIN7 / Carbanak',
}

# Manual mappings based on public CTI knowledge
MANUAL_REPORT_TO_APT = {
    "Aurora_Botnet_Command_Structure.pdf": "APT17 / DeputyDog / Axiom",
    "dukes_whitepaper.pdf": "APT29 / The Dukes / Cozy Bear",
}

REPORT_TO_APT = {**BASE_REPORT_TO_APT, **MANUAL_REPORT_TO_APT}


def clean_user_content(raw: str) -> str:
    """
    Remove the leading 'You are a cyber threat intelligence assistant.' line
    and trailing 'Task: ...' instruction, leaving just the event description
    + observed values.
    """
    lines = raw.splitlines()

    # Drop the leading system-style line if present
    if lines and lines[0].strip().startswith("You are a cyber threat intelligence assistant"):
        lines = lines[1:]

    cleaned_lines = []
    for line in lines:
        # Stop when we hit the Task instruction
        if line.strip().startswith("Task:"):
            break
        cleaned_lines.append(line)

    return "\n".join(cleaned_lines).strip()


def convert_to_qwen(input_path: str, output_path: str) -> None:
    total = 0
    written = 0
    missing_apt = 0

    with open(input_path, "r", encoding="utf-8") as fin, \
         open(output_path, "w", encoding="utf-8") as fout:

        for line in fin:
            total += 1
            line = line.strip()
            if not line:
                continue

            obj = json.loads(line)
            msgs = obj.get("messages", [])
            if len(msgs) < 2:
                # Skip malformed examples
                continue

            user_raw = msgs[0].get("content", "")
            assistant_raw = msgs[1].get("content", "")

            event_id = obj.get("event_id")
            event_date = obj.get("event_date")
            report_id = obj.get("report_id")
            apt_group = (obj.get("apt_group") or "").strip()

            # Fill missing APTs from our mapping
            if (not apt_group) and report_id in REPORT_TO_APT:
                apt_group = REPORT_TO_APT[report_id]

            if not apt_group:
                missing_apt += 1

            cleaned_user = clean_user_content(user_raw)

            new_obj = {
                "messages": [
                    {"role": "system", "content": SYS_PROMPT},
                    {"role": "user", "content": cleaned_user},
                    {"role": "assistant", "content": assistant_raw},
                ],
                "event_id": event_id,
                "event_date": event_date,
                "report_id": report_id,
                "apt_group": apt_group,
                "task_type": obj.get("task_type", "ioc_extraction"),
            }

            fout.write(json.dumps(new_obj, ensure_ascii=False) + "\n")
            written += 1

    print(f"Total input lines: {total}")
    print(f"Total output lines: {written}")
    print(f"Lines still missing apt_group: {missing_apt}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert IOC JSONL to clean Qwen chat format.")
    parser.add_argument(
        "--input",
        type=str,
        default="instruct_ioc_chat_fixed.jsonl",
        help="Path to the original JSONL file.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="instruct_ioc_qwen_clean.jsonl",
        help="Path to write the cleaned Qwen-style JSONL file.",
    )
    args = parser.parse_args()

    convert_to_qwen(args.input, args.output)
