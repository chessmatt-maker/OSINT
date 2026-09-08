import streamlit as st
from google import genai
from google.genai import types
import json

def analyze_osint_data(ground_truth_text, hibp_data, maigret_data):
    """
    Sends the aggregated OSINT data and Ground Truth to Gemini for
    entity resolution, confidence scoring, and Google Dork generation.
    """
    client = genai.Client(api_key=st.secrets["GEMINI_API_KEY"])

    prompt = f"""
    You are an expert open-source intelligence analyst conducting entity resolution for civil litigation defense. 
    Compare the provided Ground Truth data against the raw API scan results from HIBP and Maigret.

    Analyze the overlapping data points and categorize your findings into the following tiers based on the "Chain of Connection":
    - Tier 1 (Confirmed): Direct match of unique identifiers (e.g., exact email and SSN/Phone).
    - Tier 2 (Probable): Strong circumstantial overlap (e.g., matching geographic location and username).
    - Tier 3 (Unverified): Weak association requiring manual review.

    Additionally, generate 5 highly targeted Google Dork queries based on the combined intelligence to uncover public records, resumes, documents, or real footprints.
    CRITICAL FILTER REQUIREMENT FOR DORKS:
    Every generated search query MUST append exclusion operators to eliminate commercial data brokers and people-search sites. Append exclusions such as:
    -site:truepeoplesearch.com -site:fastpeoplesearch.com -site:whitepages.com -site:spokeo.com -site:beenverified.com -site:radaris.com -site:peoplefinders.com

    ### RAW DATA
    GROUND TRUTH:
    {ground_truth_text}

    HIBP BREACH DATA:
    {json.dumps(hibp_data, indent=2)}

    MAIGRET USERNAME DATA:
    {json.dumps(maigret_data, indent=2)}

    ### REQUIRED OUTPUT FORMAT
    Respond ONLY with a valid JSON object matching this exact structure:
    {{
      "tier_1_confirmed": [
        {{"finding": "Description of the match", "reasoning": "Why it is Tier 1"}}
      ],
      "tier_2_probable": [
        {{"finding": "Description of the match", "reasoning": "Why it is Tier 2"}}
      ],
      "tier_3_unverified": [
        {{"finding": "Description of the match", "reasoning": "Why it is Tier 3"}}
      ],
      "google_dorks": [
        {{"category": "Category Name", "query": "The exact dork string", "purpose": "Why run this query"}}
      ]
    }}
    """

    try:
        response = client.models.generate_content(
            model='gemini-2.5-pro',
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
            )
        )

        analyzed_results = json.loads(response.text)
        return analyzed_results

    except json.JSONDecodeError:
        return {"error": "Gemini failed to return a properly formatted JSON object."}
    except Exception as e:
        return {"error": f"Gemini API Error: {str(e)}"}