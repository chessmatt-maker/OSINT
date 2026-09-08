import requests
import streamlit as st
import subprocess
import os
import tempfile
import glob
from utils import parse_ndjson

def search_hibp(email):
    """
    Queries the Have I Been Pwned API for a given email address.
    """
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"

    # HIBP requires the api key in the header and a custom user-agent
    headers = {
        "hibp-api-key": st.secrets["HIBP_API_KEY"],
        "user-agent": "OSINT-Entity-Resolution-App"
    }

    # truncateResponse=false tells HIBP to return full breach details, not just the name
    params = {"truncateResponse": "false"}

    try:
        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return []  # 404 means no breaches found for this email, which is a valid result
        else:
            return {"error": f"HIBP API Error: {response.status_code} - {response.text}"}

    except Exception as e:
        return {"error": f"Failed to connect to HIBP: {str(e)}"}


def run_maigret(email):
    """
    Extracts the username from the email, runs the Maigret CLI via subprocess
    inside a temporary directory, parses the NDJSON results, and cleans up.
    """
    username = email.split('@')[0]

    # Use a temporary directory context so reports do not clutter the root folder
    with tempfile.TemporaryDirectory() as tmpdir:
        command = ["maigret", username, "--json", "ndjson", "--no-color", "-fo", tmpdir]

        # Force UTF-8 encoding in the environment to avoid Windows cp1252 Unicode crashes
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"

        try:
            result = subprocess.run(
                command,
                cwd=tmpdir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                env=env
            )

            # Search the temporary directory for any generated JSON or NDJSON report files
            found_files = glob.glob(os.path.join(tmpdir, "**", "*.json"), recursive=True)
            if not found_files:
                found_files = glob.glob(os.path.join(tmpdir, "**", "*.ndjson"), recursive=True)

            if found_files:
                output_path = found_files[0]
                return parse_ndjson(output_path)
            else:
                return {
                    "error": "Maigret did not create a report file.",
                    "maigret_terminal_output": result.stdout,
                    "maigret_terminal_errors": result.stderr
                }

        except FileNotFoundError:
            return {"error": "Maigret is not installed or not found in the system PATH. Run 'pip install maigret'."}