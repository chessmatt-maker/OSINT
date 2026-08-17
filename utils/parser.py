import json
import re


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

    allowed_types = {"ACCOUNT_EXTERNAL_OWNED", "EMAILADDR_COMPROMISED", "USERNAME"}

    sanitized = []
    for event in data:
        if not isinstance(event, dict):
            continue

        event_type = event.get("event_type")
        if event_type not in allowed_types:
            continue

        raw_data = event.get("data", "")
        source_data = event.get("source_data")
        record = {"event_type": event_type, "source_data": source_data}

        if event_type == "ACCOUNT_EXTERNAL_OWNED":
            parts = raw_data.split("\n", 1)
            record["platform_description"] = parts[0].strip() if parts else raw_data
            record["url"] = parts[1].strip() if len(parts) > 1 else None
        elif event_type == "EMAILADDR_COMPROMISED":
            match = re.match(r"^(.+?)\s+\[(.+?)\]$", raw_data.strip())
            if match:
                record["email"] = match.group(1).strip()
                record["breach_source"] = match.group(2).strip()
            else:
                record["data"] = raw_data
        else:
            record["data"] = raw_data

        sanitized.append(record)

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