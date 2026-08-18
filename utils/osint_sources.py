import json
import os
import tempfile
import subprocess
from urllib.parse import quote
from shutil import which

import requests
import streamlit as st


def _get_secret(name: str, default: str = "") -> str:
    value = st.secrets.get(name)
    if value:
        return str(value)
    return os.getenv(name, default)


def _split_csv(raw_value: str) -> list:
    if not raw_value:
        return []
    return [part.strip() for part in raw_value.split(",") if part.strip()]


def collect_identifiers(ground_truth: dict, extra_emails: str = "", extra_usernames: str = "") -> dict:
    gt_emails = ground_truth.get("emails", [])
    gt_usernames = ground_truth.get("usernames", [])

    if isinstance(gt_emails, str):
        gt_emails = [gt_emails]
    if isinstance(gt_usernames, str):
        gt_usernames = [gt_usernames]

    emails = {str(e).strip().lower() for e in gt_emails if str(e).strip()}
    usernames = {str(u).strip() for u in gt_usernames if str(u).strip()}

    emails.update({e.lower() for e in _split_csv(extra_emails)})
    usernames.update(_split_csv(extra_usernames))

    return {"emails": sorted(emails), "usernames": sorted(usernames)}


def query_hibp(emails: list) -> dict:
    api_key = _get_secret("HIBP_API_KEY")
    if not api_key:
        return {"results": [], "errors": ["HIBP_API_KEY is not configured."]}

    headers = {
        "hibp-api-key": api_key,
        "user-agent": "OSINT-Lit-Defense-Pipeline",
    }
    results = []
    errors = []

    for email in emails:
        try:
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}"
            resp = requests.get(url, headers=headers, params={"truncateResponse": "false"}, timeout=20)
            if resp.status_code == 404:
                results.append({"email": email, "breaches": []})
                continue
            if resp.status_code != 200:
                errors.append(f"HIBP lookup failed for {email} (status {resp.status_code}).")
                continue
            payload = resp.json()
            if isinstance(payload, list):
                results.append({"email": email, "breaches": payload})
            else:
                errors.append(f"HIBP response for {email} was not a list.")
        except Exception as exc:
            errors.append(f"HIBP lookup failed for {email}: {exc}")
    return {"results": results, "errors": errors}


def query_dehashed(emails: list, usernames: list) -> dict:
    dehashed_email = _get_secret("DEHASHED_EMAIL")
    dehashed_api_key = _get_secret("DEHASHED_API_KEY")
    if not dehashed_email or not dehashed_api_key:
        return {"results": [], "errors": ["DEHASHED_EMAIL/DEHASHED_API_KEY are not configured."]}

    queries = []
    queries.extend([f"email:{email}" for email in emails])
    queries.extend([f"username:{username}" for username in usernames])

    results = []
    errors = []
    auth = (dehashed_email, dehashed_api_key)
    for query in sorted(set(queries)):
        try:
            resp = requests.get(
                "https://api.dehashed.com/search",
                auth=auth,
                params={"query": query, "size": 100, "page": 1},
                timeout=30,
            )
            if resp.status_code == 404:
                results.append({"query": query, "entries": []})
                continue
            if resp.status_code != 200:
                errors.append(f"Dehashed query failed for {query} (status {resp.status_code}).")
                continue
            payload = resp.json()
            entries = payload.get("entries", []) if isinstance(payload, dict) else []
            if not isinstance(entries, list):
                entries = []
            results.append({"query": query, "entries": entries})
        except Exception as exc:
            errors.append(f"Dehashed query failed for {query}: {exc}")
    return {"results": results, "errors": errors}


def run_maigret_usernames(usernames: list) -> dict:
    if not usernames:
        return {"results": [], "errors": []}
    if which("maigret") is None:
        return {"results": [], "errors": ["maigret executable was not found in PATH."]}

    results = []
    errors = []
    for username in usernames:
        output_path = None
        try:
            with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False, dir="/tmp") as tmp_file:
                output_path = tmp_file.name
            cmd = [
                "maigret",
                username,
                "--json",
                output_path,
                "--timeout",
                "15",
                "--no-color",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            if proc.returncode != 0:
                errors.append(f"maigret failed for {username}: {proc.stderr.strip() or proc.stdout.strip()}")
                continue
            with open(output_path, "r", encoding="utf-8") as fp:
                payload = json.load(fp)
            results.append({"username": username, "payload": payload})
        except Exception as exc:
            errors.append(f"maigret failed for {username}: {exc}")
        finally:
            if output_path and os.path.exists(output_path):
                try:
                    os.remove(output_path)
                except Exception:
                    pass
    return {"results": results, "errors": errors}
