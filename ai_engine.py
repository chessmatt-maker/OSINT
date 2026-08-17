import json
import streamlit as st
import google.generativeai as genai

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

def evaluate_osint_data(ground_truth: dict, spiderfoot_data: list, maigret_data: list) -> dict:
    """Sends Ground Truth and sanitized OSINT data to Gemini for Tier classification."""
    
    if not initialize_gemini():
        return {}

    model = genai.GenerativeModel("gemini-1.5-pro")
    
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
          "avatar_url": "String (Extract the avatar_url or profile image URL if present, else empty string)",
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
