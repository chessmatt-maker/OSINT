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
        
        if ',' in value:
            ground_truth[key] = [v.strip() for v in value.split(',')]
        else:
            if key in ['aliases', 'locations', 'employers', 'emails', 'phones', 'usernames']:
                ground_truth[key] = [value]
            else:
                ground_truth[key] = value
                
    return ground_truth

def sanitize_spiderfoot(json_content: str) -> list:
    """Filters out low-value infrastructure nodes from SpiderFoot output."""
    try:
        data = json.loads(json_content)
    except json.JSONDecodeError:
        return []

    ignored_types = [
        "TCP_PORT_OPEN", "SSL_CERTIFICATE", "DNS_RECORD", 
        "HTTP_HEADER", "BGP_AS_OWNER", "NETBLOCK_OWNER"
    ]
    
    sanitized = []
    for event in data:
        if isinstance(event, dict) and event.get('type') not in ignored_types:
            sanitized.append({
                "type": event.get("type"),
                "data": event.get("data"),
                "module": event.get("module")
            })
            
    return sanitized

def sanitize_maigret(json_content: str) -> list:
    """Extracts valid accounts, urls, and avatars from Maigret ndjson/json."""
    try:
        data = json.loads(json_content)
    except json.JSONDecodeError:
        return []
        
    sanitized = []
    for site, details in data.items():
        if isinstance(details, dict) and details.get("status") == "Claimed":
            sanitized.append({
                "platform": site,
                "url": details.get("url_user"),
                "username": details.get("username"),
                "avatar_url": details.get("avatar_url", ""), # Thumbnail URL captured here
                "tags": details.get("tags", [])
            })
            
    return sanitized
