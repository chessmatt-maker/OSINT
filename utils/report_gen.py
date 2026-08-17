import io
from datetime import datetime
from docxtpl import DocxTemplate


def generate_docx_report(ground_truth: dict, ai_analysis: dict,
                         template_path="templates/report_template.docx") -> io.BytesIO:
    """Renders the final Word document using docxtpl."""

    doc = DocxTemplate(template_path)

    # Categorize findings based on Vertex AI classification
    findings = ai_analysis.get("findings", [])
    high_confidence = [f for f in findings if f["confidence_tier"] in ["Tier 1", "Tier 2"]]
    dubious = [f for f in findings if f["confidence_tier"] == "Tier 3"]

    # Map context dictionary for docxtpl tags
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

    # Save to a BytesIO object for Streamlit download
    doc_io = io.BytesIO()
    doc.save(doc_io)
    doc_io.seek(0)

    return doc_io