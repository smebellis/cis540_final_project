
import argparse
import csv
import json
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple, Optional
from urllib.parse import urlparse
import ipaddress
import ast

ALLOWED_ROLES = {"system", "user", "assistant"}

# Regexes for IOC extraction (fallback scan)
RE_IP = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})\b')
RE_DOMAIN = re.compile(r'\b(?=.{1,253}\b)(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b')
RE_URL = re.compile(r'\b(?:https?://|ftp://)[^\s<>\)"]+\b', re.IGNORECASE)
RE_DATE_LIKE = re.compile(r'\b(\d{4})-(\d{2})-(\d{2})\b')

def try_parse_simple_yaml_block(text: str) -> Optional[Dict[str, Any]]:
    lines = text.splitlines()
    data: Dict[str, Any] = {}
    current_key = None
    indent_level = None
    for ln in lines:
        if not ln.strip():
            continue
        m_key = re.match(r'^([A-Za-z0-9_\-\.]+)\s*:\s*$', ln.strip())
        if m_key:
            current_key = m_key.group(1)
            data[current_key] = []
            indent_level = None
            continue
        m_kv = re.match(r'^([A-Za-z0-9_\-\.]+)\s*:\s*(.+)$', ln.strip())
        if m_kv:
            k = m_kv.group(1)
            v = m_kv.group(2).strip()
            data[k] = v
            current_key = None
            indent_level = None
            continue
        m_item = re.match(r'^(\s*)-\s*(.+)$', ln)
        if m_item and current_key is not None:
            if indent_level is None:
                indent_level = len(m_item.group(1))
            data[current_key].append(m_item.group(2).strip())
            continue
        return None
    return data if data else None

def to_iso_utc(date_str: str) -> Optional[str]:
    if not isinstance(date_str, str):
        return None
    s = date_str.strip()
    try:
        if s.endswith("Z"):
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        else:
            dt = datetime.fromisoformat(s)
        return dt.astimezone(timezone.utc).replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        pass
    m = RE_DATE_LIKE.search(s)
    if m:
        y, mo, d = m.groups()
        try:
            dt = datetime(int(y), int(mo), int(d), tzinfo=timezone.utc)
            return dt.isoformat().replace("+00:00", "Z")
        except Exception:
            return None
    return None

def validate_role_messages(record: Dict[str, Any], warnings: List[Dict[str, Any]]) -> bool:
    ok = True
    msgs = record.get("messages")
    if not isinstance(msgs, list) or not msgs:
        warnings.append({"type": "schema", "issue": "missing_or_empty_messages", "detail": "messages must be a non-empty list"})
        return False
    for i, m in enumerate(msgs):
        if not isinstance(m, dict):
            warnings.append({"type": "schema", "issue": "message_not_object", "detail": f"message[{i}] is {type(m)}"})
            ok = False
            continue
        role = m.get("role")
        content = m.get("content")
        if role not in ALLOWED_ROLES:
            warnings.append({"type": "schema", "issue": "invalid_role", "detail": f"message[{i}].role={role}"})
            ok = False
        if not isinstance(content, str) or content.strip() == "":
            warnings.append({"type": "schema", "issue": "empty_or_nonstring_content", "detail": f"message[{i}].content invalid"})
            ok = False
    return ok

def extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    urls = RE_URL.findall(text)
    ips = RE_IP.findall(text)
    domains = RE_DOMAIN.findall(text)

    def dedup(seq):
        seen = set()
        out = []
        for x in seq:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    return {"ip": dedup(ips), "url": dedup(urls), "domain": dedup(domains)}

def validate_ip(ip_str: str) -> bool:
    try:
        import ipaddress
        ipaddress.ip_address(ip_str)
        return True
    except Exception:
        return False

def validate_url(url_str: str) -> bool:
    try:
        from urllib.parse import urlparse
        p = urlparse(url_str)
        return bool(p.scheme and p.netloc)
    except Exception:
        return False

def scan_and_warn_content(text: str, warnings: List[Dict[str, Any]], context: str):
    parsed = try_parse_simple_yaml_block(text)
    iocs = extract_iocs_from_text(text)
    invalid_ips = []
    invalid_urls = []

    if isinstance(parsed, dict):
        for key in ["ip-src", "ip", "ips", "ipdst", "ipsrc"]:
            val = parsed.get(key)
            if isinstance(val, list):
                for ip in val:
                    if not validate_ip(ip):
                        invalid_ips.append(ip)
        for key in ["url", "urls"]:
            val = parsed.get(key)
            if isinstance(val, list):
                for u in val:
                    if not validate_url(u) and not RE_DOMAIN.fullmatch(u):
                        invalid_urls.append(u)

    for ip in iocs["ip"]:
        if not validate_ip(ip):
            invalid_ips.append(ip)
    for u in iocs["url"]:
        if not validate_url(u):
            invalid_urls.append(u)

    if invalid_ips:
        warnings.append({"type": "content", "issue": "invalid_ip", "detail": {"context": context, "values": sorted(set(invalid_ips))}})
    if invalid_urls:
        warnings.append({"type": "content", "issue": "invalid_url_like", "detail": {"context": context, "values": sorted(set(invalid_urls))}})

    suspicious_domains = [d for d in iocs["domain"] if "." not in d or len(d) < 3]
    if suspicious_domains:
        warnings.append({"type": "content", "issue": "suspicious_domain", "detail": {"context": context, "values": sorted(set(suspicious_domains))}})

def normalize_dates(record: Dict[str, Any], warnings: List[Dict[str, Any]], date_keys: List[str] = ["event_date", "date_observed", "timestamp_observed"]) -> None:
    for k in date_keys:
        if k in record:
            v = record[k]
            if isinstance(v, str):
                iso = to_iso_utc(v)
                if iso and iso != v:
                    record[k] = iso
                    warnings.append({"type": "normalize", "issue": "date_normalized", "detail": {k: iso}})
                elif not iso:
                    warnings.append({"type": "content", "issue": "unparseable_date_string", "detail": {k: v}})
            elif isinstance(v, (int, float)):
                try:
                    iso = datetime.fromtimestamp(v, tz=timezone.utc).isoformat().replace("+00:00", "Z")
                    record[k] = iso
                    warnings.append({"type": "normalize", "issue": "date_epoch_to_iso", "detail": {k: iso}})
                except Exception:
                    warnings.append({"type": "content", "issue": "unparseable_date_epoch", "detail": {k: v}})
            else:
                s = str(v)
                iso = to_iso_utc(s)
                if iso:
                    record[k] = iso
                    warnings.append({"type": "normalize", "issue": "date_repr_to_iso", "detail": {k: iso}})
                else:
                    warnings.append({"type": "content", "issue": "unserializable_date", "detail": {k: s}})

def process_record(raw_line: str, attempt_python_literal: bool, hard_errors: List[str]) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(raw_line)
    except json.JSONDecodeError as e:
        if attempt_python_literal:
            try:
                obj = ast.literal_eval(raw_line)
                return obj
            except Exception as e2:
                hard_errors.append(f"Line not JSON and literal_eval failed: {e2}")
                return None
        else:
            hard_errors.append(f"Line not valid JSON: {e}")
            return None

def validate_file(input_path: str, output_path: str, report_csv: Optional[str] = None, attempt_python_literal: bool = False, skip_bad_lines: bool = True) -> Tuple[int, int]:
    n_in = 0
    n_out = 0
    warnings_all: List[Dict[str, Any]] = []
    hard_errors: List[str] = []

    with open(input_path, "r", encoding="utf-8") as fin, open(output_path, "w", encoding="utf-8") as fout:
        for line in fin:
            n_in += 1
            line = line.strip()
            if not line:
                continue
            rec = process_record(line, attempt_python_literal, hard_errors)
            if rec is None:
                if skip_bad_lines:
                    continue
                else:
                    warnings_all.append({"type": "schema", "issue": "unreadable_line", "detail": {"line": n_in}})
                    continue

            local_warnings: List[Dict[str, Any]] = []
            ok_messages = validate_role_messages(rec, local_warnings)
            normalize_dates(rec, local_warnings)

            msgs = rec.get("messages", [])
            for i, m in enumerate(msgs if isinstance(msgs, list) else []):
                content = m.get("content", "")
                if isinstance(content, str) and content.strip():
                    scan_and_warn_content(content, local_warnings, context=f"messages[{i}].{m.get('role')}")

            if not ok_messages:
                local_warnings.append({"type": "schema", "issue": "messages_invalid", "detail": f"record {n_in} has invalid messages"})

            for w in local_warnings:
                w = dict(w)
                w["line"] = n_in
                warnings_all.append(w)

            try:
                fout.write(json.dumps(rec, ensure_ascii=False) + "\n")
                n_out += 1
            except TypeError as e:
                hard_errors.append(f"Non-serializable record at line {n_in}: {e}")
                if not skip_bad_lines:
                    minimal = {"messages": [{"role": "system", "content": "UNSERIALIZABLE_RECORD"}]}
                    fout.write(json.dumps(minimal, ensure_ascii=False) + "\n")
                    n_out += 1

    if report_csv:
        with open(report_csv, "w", encoding="utf-8", newline="") as fcsv:
            writer = csv.DictWriter(fcsv, fieldnames=["line", "type", "issue", "detail"])
            writer.writeheader()
            for w in warnings_all:
                detail = w.get("detail")
                if not isinstance(detail, str):
                    detail = json.dumps(detail, ensure_ascii=False)
                writer.writerow({
                    "line": w.get("line", ""),
                    "type": w.get("type", ""),
                    "issue": w.get("issue", ""),
                    "detail": detail
                })

    print("==== Validation Summary ====")
    print(f"Input lines       : {n_in}")
    print(f"Output lines      : {n_out}")
    print(f"Warnings          : {len(warnings_all)}")
    print(f"Hard parse errors : {len(hard_errors)}")
    if hard_errors:
        for he in hard_errors[:10]:
            print("  -", he)
        if len(hard_errors) > 10:
            print(f"  ... and {len(hard_errors) - 10} more")

    return n_in, n_out

def main():
    parser = argparse.ArgumentParser(description="Validate and fix IOC chat JSONL dataset.")
    parser.add_argument("--in", dest="input_path", required=True, help="Input JSONL path")
    parser.add_argument("--out", dest="output_path", required=True, help="Output (fixed) JSONL path")
    parser.add_argument("--report", dest="report_csv", default=None, help="Warnings report CSV path")
    parser.add_argument("--attempt-python-literal", action="store_true", help="Attempt ast.literal_eval on non-JSON lines")
    parser.add_argument("--no-skip-bad-lines", action="store_true", help="Do not skip unreadable lines; keep alignment")
    args = parser.parse_args()

    validate_file(
        input_path=args.input_path,
        output_path=args.output_path,
        report_csv=args.report_csv,
        attempt_python_literal=args.attempt_python_literal,
        skip_bad_lines=not args.no_skip_bad_lines
    )

if __name__ == "__main__":
    main()
