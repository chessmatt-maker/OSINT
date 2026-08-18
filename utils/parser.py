import json
import re
import ast
from urllib.parse import urlparse


def parse_ground_truth(file_content: str) -> dict:
    """Parses ground_truth.txt into a JSON-compatible dictionary."""
    ground_truth = {}
    lines = file_content.strip().split('\n')

    for line in lines:
        if ':' not in line:
            continue

        key, value = line.split(':', 1)
        key = key.strip().lower().replace(' ', '_')
        value = value.strip()

        # If the value contains commas, treat it as a list
        if ',' in value:
            ground_truth[key] = [v.strip() for v in value.split(',')]
        else:
            # Convert keys to plural lists where appropriate even if single item
            if key in ['aliases', 'locations', 'employers', 'emails', 'phones', 'usernames']:
                ground_truth[key] = [value]
            else:
                ground_truth[key] = value

    return ground_truth


def sanitize_spiderfoot(json_content: str) -> list:
    """Aggressively filters SpiderFoot JSON exports to retain only actionable intelligence."""
    try:
        data = json.loads(json_content)
    except json.JSONDecodeError:
        return []

    if isinstance(data, dict):
        if isinstance(data.get("events"), list):
            data = data["events"]
        else:
            return []
    if not isinstance(data, list):
        return []

    allowed_types = {
        "HUMAN_NAME",
        "AFFILIATE_EMAILADDR",
        "EMAILADDR",
        "USERNAME",
        "ACCOUNT_EXTERNAL_OWNED",
        "EMAILADDR_COMPROMISED",
        "RAW_RIR_DATA",
    }
    account_platform_whitelist = {
        "github",
        "gitlab",
        "bitbucket",
        "docker",
        "dockerhub",
        "npm",
        "pypi",
        "rubygems",
        "keybase",
        "venmo",
        "paypal",
        "cashapp",
        "coinbase",
        "binance",
        "kraken",
        "stripe",
        "revolut",
        "wise",
    }
    rir_keep_fields = {"firstName", "lastName", "companyName", "city", "state", "email", "pocRef"}

    def _clean_value(value):
        if value is None:
            return None
        if isinstance(value, str):
            value = value.strip()
            return value if value else None
        return value

    def _normalize_space(value: str) -> str:
        return re.sub(r"\s+", " ", value or "").strip()

    def _dedupe_key(payload: dict) -> str:
        return json.dumps(payload, sort_keys=True, ensure_ascii=False)

    def _parse_rir_dict(raw_value):
        if isinstance(raw_value, dict):
            return raw_value
        if not isinstance(raw_value, str):
            return None
        text = raw_value.strip()
        if not text:
            return None
        for loader in (json.loads, ast.literal_eval):
            try:
                parsed = loader(text)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                continue
        return None

    def _normalize_rir_key(key: str) -> str:
        key = str(key).split("}")[-1]
        key = str(key).split(":")[-1]
        return key.strip().lower()

    def _extract_rir_fields(raw_value):
        parsed = _parse_rir_dict(raw_value)
        if not parsed:
            return {}

        wanted = {k.lower(): k for k in rir_keep_fields}
        found = {}

        def walk(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    normalized_key = _normalize_rir_key(k)
                    if normalized_key in wanted:
                        out_key = wanted[normalized_key]
                        if out_key not in found:
                            cleaned = _clean_value(v)
                            if cleaned is not None:
                                found[out_key] = cleaned
                    walk(v)
            elif isinstance(obj, list):
                for item in obj:
                    walk(item)

        walk(parsed)
        return found

    def _platform_allowed(description: str, account_url: str) -> bool:
        desc = (description or "").lower()
        host = ""
        if isinstance(account_url, str) and account_url.strip():
            try:
                host = (urlparse(account_url).hostname or "").lower()
            except Exception:
                host = ""
        for token in account_platform_whitelist:
            if token in desc or token in host:
                return True
        return False

    sanitized = []
    seen = set()
    breach_by_email = {}
    for event in data:
        if not isinstance(event, dict):
            continue

        event_type = event.get("event_type") or event.get("type")
        if event_type not in allowed_types:
            continue

        raw_data = _clean_value(event.get("data", ""))
        source_data = event.get("source_data")
        module_name = event.get("module")
        record = {"event_type": event_type}
        if source_data:
            record["source_data"] = source_data

        if event_type == "ACCOUNT_EXTERNAL_OWNED":
            if not isinstance(raw_data, str):
                continue
            parts = raw_data.split("\n", 1)
            platform_description = _normalize_space(parts[0]) if parts else _normalize_space(raw_data)
            account_url = _normalize_space(parts[1]) if len(parts) > 1 else None
            if not _platform_allowed(platform_description, account_url):
                continue
            record["platform_description"] = platform_description
            if account_url:
                record["url"] = account_url
        elif event_type == "EMAILADDR_COMPROMISED":
            if not isinstance(raw_data, str):
                continue
            match = re.match(r"^(.+?)\s+\[(.+?)\]$", raw_data.strip())
            if match:
                email = match.group(1).strip().lower()
                breach_source = _normalize_space(match.group(2))
            else:
                email = None
                breach_source = _normalize_space(raw_data)
            if not email:
                continue
            entry = breach_by_email.setdefault(email, {"breaches": set(), "sources": set()})
            if breach_source:
                entry["breaches"].add(breach_source)
            if module_name:
                entry["sources"].add(str(module_name).strip())
            continue
        elif event_type == "RAW_RIR_DATA":
            extracted = _extract_rir_fields(raw_data)
            if not extracted:
                continue
            record["rir"] = extracted
        else:
            if raw_data is None:
                continue
            if isinstance(raw_data, str):
                raw_data = _normalize_space(raw_data)
            record["data"] = raw_data

        key = _dedupe_key(record)
        if key in seen:
            continue
        seen.add(key)
        sanitized.append(record)

    for email, info in breach_by_email.items():
        breach_record = {
            "event_type": "EMAILADDR_COMPROMISED",
            "email": email,
            "breaches": sorted(info["breaches"]),
        }
        if info["sources"]:
            breach_record["sources"] = sorted(info["sources"])
        key = _dedupe_key(breach_record)
        if key in seen:
            continue
        seen.add(key)
        sanitized.append(breach_record)

    return sanitized


def sanitize_maigret(json_content: str) -> list:
    """Extracts valid accounts and urls from Maigret ndjson/json."""
    try:
        data = json.loads(json_content)
    except json.JSONDecodeError:
        return []

    sanitized = []
    # Maigret typically nests findings under site names
    for site, details in data.items():
        if isinstance(details, dict) and details.get("status") == "Claimed":
            sanitized.append({
                "platform": site,
                "url": details.get("url_user"),
                "username": details.get("username"),
                "tags": details.get("tags", [])
            })

    return sanitized