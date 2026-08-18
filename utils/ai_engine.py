import json
import streamlit as st
import google.generativeai as genai


def _normalize_str(value: str) -> str:
    return (value or "").strip().lower()


def _to_set(value) -> set:
    if value is None:
        return set()
    if isinstance(value, str):
        return {_normalize_str(value)} if value.strip() else set()
    if isinstance(value, list):
        return {_normalize_str(v) for v in value if str(v).strip()}
    return set()


def initialize_gemini():
    """Initializes the Gemini API using the key from Streamlit secrets."""
    try:
        api_key = st.secrets["GEMINI_API_KEY"]
        genai.configure(api_key=api_key)
        return True
    except KeyError:
        st.error("GEMINI_API_KEY not found in Streamlit secrets. Please add it.")
        return False
    except Exception as e:
        st.error(f"Failed to initialize Gemini API: {str(e)}")
        return False

def filter_by_ground_truth(ground_truth: dict, spiderfoot_data: list) -> dict:
    """
    Scores sanitized SpiderFoot events against known ground-truth attributes and
    categorises them into verified_matches, probable_matches, divergent_identities,
    unverified_noise, and actionable_contact_vectors.
    """
    if not initialize_gemini():
        return {}

    model = genai.GenerativeModel("gemini-2.5-flash")

    prompt = f"""
    You are an expert intelligence analyst assisting civil litigation defense attorneys.
    You have been given a set of sanitized SpiderFoot events and a ground-truth baseline
    for a specific target individual.  Your task is to score every event against the
    ground-truth and populate the schema below — do NOT invent or hallucinate data.

    Ground Truth Baseline:
    {json.dumps(ground_truth, indent=2)}

    Sanitized SpiderFoot Events:
    {json.dumps(spiderfoot_data, indent=2)}

    Classify each event into exactly one of the four categories:

    - verified_matches: Events whose data EXACTLY matches a ground-truth attribute
      (e.g., the exact phone number, email address, or full name from ground truth).
      Return as an array of plain strings describing the match.

    - probable_matches: Events with PARTIAL matches (e.g., same last name AND same
      state, or a username that matches a known alias).
      Return as an array of plain strings describing the probable link.

    - divergent_identities: Events that CONFLICT with ground truth (e.g., a
      different first name, a different city that contradicts known location).
      Return as an array of objects with "conflict_reason" (string) and
      "raw_data" (string) fields.

    - unverified_noise: Generic usernames, email addresses, or accounts that cannot
      be definitively linked OR unlinked to the ground truth target.
      Return as an array of plain strings.

    After classification, populate actionable_contact_vectors with the BEST verified
    primary_phone and primary_email drawn ONLY from verified_matches; leave those
    fields as empty strings if no verified match exists.

    Respond STRICTLY in this JSON schema:
    {{
      "ground_truth_baseline": {{
        "target_name": "{ground_truth.get('primary_name', ground_truth.get('name', ''))}",
        "target_dob": "{ground_truth.get('dob', '')}",
        "target_emails": {json.dumps(ground_truth.get('emails', []))},
        "target_phones": {json.dumps(ground_truth.get('phones', []))},
        "target_location": "{', '.join(ground_truth.get('locations', []))}"
      }},
      "filtered_results": {{
        "verified_matches": ["..."],
        "probable_matches": ["..."],
        "divergent_identities": [
          {{"conflict_reason": "...", "raw_data": "..."}}
        ],
        "unverified_noise": ["..."]
      }},
      "actionable_contact_vectors": {{
        "primary_phone": "",
        "primary_email": ""
      }}
    }}
    """

    try:
        response = model.generate_content(
            prompt,
            generation_config=genai.GenerationConfig(
                response_mime_type="application/json"
            )
        )
        return json.loads(response.text)
    except Exception as e:
        st.error(f"Ground Truth Filtering failed: {str(e)}")
        return {}


def evaluate_osint_data(ground_truth: dict, spiderfoot_data: list, maigret_data: list) -> dict:
    """Sends Ground Truth and sanitized OSINT data to Gemini for Tier classification."""

    if not initialize_gemini():
        return {}

    model = genai.GenerativeModel("gemini-2.5-flash")

    prompt = f"""
    You are an expert intelligence analyst assisting civil litigation defense attorneys.
    Your task is to evaluate raw OSINT findings against verified Ground Truth data, establishing a "Chain of Connection".
    
    Ground Truth Data:
    {json.dumps(ground_truth, indent=2)}
    
    SpiderFoot Findings (Sanitized):
    {json.dumps(spiderfoot_data, indent=2)}
    
    Maigret Findings (Sanitized):
    {json.dumps(maigret_data, indent=2)}
    
    Evaluate every candidate hit and assign it to one of three tiers:
    - Tier 1 (Confirmed Match): Direct connection to a verified Ground Truth item.
    - Tier 2 (Probable Lead): Matches a unique username pattern + contains geographic anchor or known employer.
    - Tier 3 (Dubious): Name or generic username match, but lacks secondary corroboration. Requires manual verification.

    Also generate 5 targeted Google Dork queries based on the ground truth identifiers (e.g., site:facebook.com "John Doe" AND "Munford").
    
    Respond STRICTLY in JSON format with the following schema:
    {{
      "findings": [
        {{
          "platform": "String (e.g., Instagram, LinkedIn)",
          "url": "String",
          "confidence_tier": "Tier 1, Tier 2, or Tier 3",
          "connection_explanation": "Plain English sentence starting from a known identifier.",
          "case_relevance": "Why an attorney cares.",
          "is_dubious": boolean
        }}
      ],
      "google_dorks": [
        "query 1", "query 2"
      ],
      "executive_summary": "High-level narrative of material findings (2-3 paragraphs)."
    }}
    """

    try:
        # Enforce JSON output structure via generation config
        response = model.generate_content(
            prompt,
            generation_config=genai.GenerationConfig(
                response_mime_type="application/json"
            )
        )
        return json.loads(response.text)
    except Exception as e:
        st.error(f"AI Evaluation failed: {str(e)}")
        return {}


def compare_external_findings(
    ground_truth: dict,
    maigret_data: list,
    hibp_data: list,
    dehashed_data: list,
) -> dict:
    """
    Deterministically compare external-source findings against ground truth and
    bucket into confirmed/probable/unrelated categories.
    """
    gt_emails = _to_set(ground_truth.get("emails", []))
    gt_usernames = _to_set(ground_truth.get("usernames", []))
    gt_names = _to_set([ground_truth.get("primary_name", ""), *(ground_truth.get("aliases", []) or [])])

    confirmed = []
    probable = []
    unrelated = []

    for item in maigret_data or []:
        username = _normalize_str(item.get("username", ""))
        platform = item.get("platform", "Unknown")
        url = item.get("url", "")
        if username and username in gt_usernames:
            confirmed.append({
                "source": "Maigret",
                "match_type": "username_exact",
                "platform": platform,
                "url": url,
                "detail": f"Exact username match on {platform}: {item.get('username', '')}",
            })
        elif username:
            probable.append({
                "source": "Maigret",
                "match_type": "username_candidate",
                "platform": platform,
                "url": url,
                "detail": f"Potential account on {platform}: {item.get('username', '')}",
            })

    for item in hibp_data or []:
        email = _normalize_str(item.get("email", ""))
        breach_name = item.get("breach_name", "") or item.get("title", "")
        detail = f"Breach '{breach_name}' for {item.get('email', '')}".strip()
        record = {
            "source": "HIBP",
            "match_type": "email_breach",
            "email": item.get("email", ""),
            "breach_name": breach_name,
            "detail": detail,
            "data_classes": item.get("data_classes", []),
        }
        if email in gt_emails:
            confirmed.append(record)
        elif email:
            probable.append(record)
        else:
            unrelated.append(record)

    for item in dehashed_data or []:
        email = _normalize_str(item.get("email", ""))
        username = _normalize_str(item.get("username", ""))
        name = _normalize_str(item.get("name", ""))
        db_name = item.get("database_name", "")
        record = {
            "source": "Dehashed",
            "match_type": "credential_exposure",
            "email": item.get("email", ""),
            "username": item.get("username", ""),
            "name": item.get("name", ""),
            "database_name": db_name,
            "detail": f"Credential record in '{db_name}' (email={item.get('email', '')}, username={item.get('username', '')})",
        }
        if email and email in gt_emails:
            confirmed.append(record)
        elif username and username in gt_usernames:
            confirmed.append(record)
        elif name and name in gt_names:
            probable.append(record)
        else:
            unrelated.append(record)

    return {
        "confirmed": confirmed,
        "probable": probable,
        "unrelated": unrelated,
        "counts": {
            "confirmed": len(confirmed),
            "probable": len(probable),
            "unrelated": len(unrelated),
        },
    }