import requests
import streamlit as st
import subprocess
import os
import tempfile
import glob
import json
import phonenumbers
import whois
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


def run_holehe(email):
    """
    Executes holehe via subprocess to check registered accounts for an email.
    Parses JSON/stdout output and returns structured results.
    """
    try:
        command = ["holehe", email, "--json"]
        
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8"
        )
        
        if result.returncode == 0:
            try:
                # Try to parse as JSON
                holehe_output = json.loads(result.stdout)
                return holehe_output
            except json.JSONDecodeError:
                # If not JSON, return the raw stdout
                return {
                    "raw_output": result.stdout,
                    "stderr": result.stderr
                }
        else:
            return {
                "error": f"Holehe exited with code {result.returncode}",
                "stderr": result.stderr
            }
    
    except FileNotFoundError:
        return {"error": "Holehe is not installed. Run 'pip install holehe'."}
    except Exception as e:
        return {"error": f"Failed to run Holehe: {str(e)}"}


def run_sherlock(username):
    """
    Executes sherlock via subprocess on a username to enumerate social media accounts.
    Parses the JSON output and returns results.
    """
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            command = ["sherlock", username, "--json", "-o", tmpdir]
            
            result = subprocess.run(
                command,
                cwd=tmpdir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8"
            )
            
            # Look for generated JSON report files
            found_files = glob.glob(os.path.join(tmpdir, "**", "*.json"), recursive=True)
            
            if found_files:
                output_path = found_files[0]
                try:
                    with open(output_path, 'r', encoding='utf-8') as f:
                        sherlock_data = json.load(f)
                    return sherlock_data
                except Exception as e:
                    return {"error": f"Failed to parse Sherlock JSON: {str(e)}"}
            else:
                return {
                    "raw_output": result.stdout,
                    "stderr": result.stderr,
                    "note": "Sherlock did not produce a JSON file"
                }
    
    except FileNotFoundError:
        return {"error": "Sherlock is not installed. Run 'pip install sherlock-project'."}
    except Exception as e:
        return {"error": f"Failed to run Sherlock: {str(e)}"}


def get_phone_info(phone_string):
    """
    Uses the phonenumbers library to parse a raw phone number string,
    format it to E.164, and extract carrier, timezone, and geographic location.
    Returns structured phone metadata.
    """
    try:
        # Try to parse the phone number (defaults to US if no region provided)
        parsed_phone = phonenumbers.parse(phone_string, "US")
        
        if not phonenumbers.is_valid_number(parsed_phone):
            return {"error": f"Invalid phone number: {phone_string}"}
        
        # Format to E.164
        e164_format = phonenumbers.format_number(parsed_phone, phonenumbers.PhoneNumberFormat.E164)
        
        # Get geographic location
        from phonenumbers import geocoder
        location = geocoder.description_for_number(parsed_phone, "en")
        
        # Get timezone
        from phonenumbers import timezone
        timezones = timezone.time_zones_for_number(parsed_phone)
        tz = timezones[0] if timezones else "Unknown"
        
        # Get carrier info
        from phonenumbers import carrier
        carrier_name = carrier.name_for_number(parsed_phone, "en")
        
        return {
            "raw_input": phone_string,
            "e164_format": e164_format,
            "location": location if location else "Unknown",
            "timezone": tz,
            "carrier": carrier_name if carrier_name else "Unknown",
            "country_code": parsed_phone.country_code,
            "national_number": parsed_phone.national_number
        }
    
    except phonenumbers.NumberParseException as e:
        return {"error": f"Failed to parse phone number: {str(e)}"}
    except Exception as e:
        return {"error": f"Failed to extract phone info: {str(e)}"}


def get_whois_info(domain):
    """
    Uses python-whois to extract domain registration data including
    registrant name, organization, and creation date.
    """
    try:
        whois_data = whois.whois(domain)
        
        # Extract key fields
        result = {
            "domain": domain,
            "registrant_name": whois_data.get("name", "Unknown"),
            "registrant_organization": whois_data.get("org", "Unknown"),
            "creation_date": str(whois_data.get("creation_date", "Unknown")),
            "expiration_date": str(whois_data.get("expiration_date", "Unknown")),
            "registrar": whois_data.get("registrar", "Unknown"),
            "registrant_email": whois_data.get("registrant_email", "Unknown"),
            "admin_email": whois_data.get("admin_email", "Unknown"),
            "name_servers": whois_data.get("name_servers", [])
        }
        
        return result
    
    except Exception as e:
        return {"error": f"Failed to retrieve WHOIS info for {domain}: {str(e)}"}
