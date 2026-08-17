import io
import requests
from datetime import datetime
from docxtpl import DocxTemplate, InlineImage
from docx.shared import Mm

def fetch_thumbnail(doc, url: str):
    """Downloads an image URL and returns a Word-compatible InlineImage."""
    if not url:
        return ""
    try:
        # Download the image with a short timeout so the app doesn't hang on dead links
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            image_stream = io.BytesIO(response.content)
            # Mm(25) sets the image width to 25 millimeters (about 1 inch)
            return InlineImage(doc, image_descriptor=image_stream, width=Mm(25))
    except Exception:
        pass
    return ""

def generate_docx_report(ground_truth: dict, ai_analysis: dict, template_path="templates/report_template.docx") -> io.BytesIO:
    """Renders the final Word document using docxtpl."""
    
    doc = DocxTemplate(template_path)
    
    findings = ai_analysis.get("findings", [])
    
    # Process images for all findings before rendering
    for finding in findings:
        finding['thumbnail'] = fetch_thumbnail(doc, finding.get('avatar_url', ''))

    high_confidence = [f for f in findings if f["confidence_tier"] in ["Tier 1", "Tier 2"]]
    dubious = [f for f in findings if f["confidence_tier"] == "Tier 3"]
    
    context = {
        "report_date": datetime.now().strftime("%B %d, %Y"),
        "subject_name": ground_truth.get("primary_name", "Unknown Subject"),
        "dob": ground_truth.get("dob", "N/A"),
        "known_locations": ", ".join(ground_truth.get("locations", [])),
        "known_emails": ", ".join(ground_truth.get("emails", [])),
        "executive_summary": ai_analysis.get("executive_summary", "No summary generated."),
        "high_confidence_findings": high_confidence,
        "has_high_confidence": len(high_confidence) > 0,
        "dubious_findings": dubious,
        "has_dubious": len(dubious) > 0,
        "google_dorks": ai_analysis.get("google_dorks", [])
    }
    
    doc.render(context)
    
    doc_io = io.BytesIO()
    doc.save(doc_io)
    doc_io.seek(0)
    
    return doc_io
