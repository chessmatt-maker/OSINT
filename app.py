import streamlit as st
import json

from utils.parser import (
    parse_ground_truth,
    sanitize_maigret,
    sanitize_hibp,
    sanitize_dehashed,
)
from utils.ai_engine import evaluate_osint_data, filter_by_ground_truth, compare_external_findings
from utils.report_gen import generate_docx_report, generate_pdf_report
from utils.osint_sources import collect_identifiers, query_hibp, query_dehashed, run_maigret_usernames

st.set_page_config(page_title="OSINT Lit-Defense Pipeline", layout="wide", page_icon="⚖️")

st.title("⚖️ OSINT Pipeline for Civil Litigation")
st.markdown("Automated intake, AI-driven filtering, and litigation-ready report generation.")

# --- SIDEBAR: Direct Inputs ---
st.sidebar.header("1. Data Ingestion")
gt_file = st.sidebar.file_uploader("Upload Ground Truth (.txt)", type=["txt"])
st.sidebar.header("2. Optional Direct Inputs")
extra_emails = st.sidebar.text_area("Emails (comma-separated)", placeholder="john@example.com, jane@example.com")
extra_usernames = st.sidebar.text_area("Usernames (comma-separated)", placeholder="john_doe, jdoe1988")

if st.sidebar.button("Run OSINT Evaluation", type="primary"):
    if not gt_file:
        st.sidebar.error("Please upload Ground Truth.")
    else:
        # --- PROCESSING PIPELINE ---
        with st.spinner("Step 1: Parsing and Sanitizing Input Data..."):
            gt_text = gt_file.getvalue().decode("utf-8")
            ground_truth = parse_ground_truth(gt_text)
            identifiers = collect_identifiers(ground_truth, extra_emails, extra_usernames)
            if not (identifiers.get("emails") or identifiers.get("usernames")):
                st.sidebar.error("Please provide at least one email or username in Ground Truth or the direct inputs.")
                st.stop()
            mg_sanitized = []

        with st.spinner("Step 2: Running HIBP/Dehashed lookups and Maigret scans..."):
            hibp_result = query_hibp(identifiers.get("emails", []))
            dehashed_result = query_dehashed(
                identifiers.get("emails", []),
                identifiers.get("usernames", []),
            )
            maigret_runtime_result = run_maigret_usernames(identifiers.get("usernames", []))

            for scan in maigret_runtime_result.get("results", []):
                payload = scan.get("payload")
                if payload is None:
                    continue
                mg_sanitized.extend(sanitize_maigret(json.dumps(payload)))

            hibp_sanitized = sanitize_hibp(hibp_result.get("results", []))
            dehashed_sanitized = sanitize_dehashed(dehashed_result.get("results", []))

            source_errors = (
                hibp_result.get("errors", [])
                + dehashed_result.get("errors", [])
                + maigret_runtime_result.get("errors", [])
            )

        with st.spinner("Step 3: Filtering external results against Ground Truth..."):
            gt_filter_results = filter_by_ground_truth(ground_truth, [])
            external_summary = compare_external_findings(
                ground_truth,
                mg_sanitized,
                hibp_sanitized,
                dehashed_sanitized,
            )

        with st.spinner("Step 4: Connecting to Vertex AI for Connection Chain Analysis..."):
            analysis_results = evaluate_osint_data(ground_truth, [], mg_sanitized)

        if analysis_results:
            st.success("Analysis Complete!")
            if source_errors:
                st.warning("Some external lookups could not complete:\n- " + "\n- ".join(source_errors))

            st.header("📡 External Source Comparison")
            counts = external_summary.get("counts", {})
            col_c, col_p, col_u = st.columns(3)
            col_c.metric("Confirmed", counts.get("confirmed", 0))
            col_p.metric("Probable", counts.get("probable", 0))
            col_u.metric("Unrelated", counts.get("unrelated", 0))

            with st.expander("Confirmed Findings", expanded=True):
                for item in external_summary.get("confirmed", []):
                    st.success(item.get("detail", ""))
            with st.expander("Probable Findings", expanded=False):
                for item in external_summary.get("probable", []):
                    st.warning(item.get("detail", ""))
            with st.expander("Unrelated/Noise", expanded=False):
                for item in external_summary.get("unrelated", []):
                    st.info(item.get("detail", ""))

            # --- Ground Truth Filter Results ---
            if gt_filter_results:
                st.header("🔍 Ground Truth Filter Results")
                fr = gt_filter_results.get("filtered_results", {})

                acv = gt_filter_results.get("actionable_contact_vectors", {})
                if acv.get("primary_phone") or acv.get("primary_email"):
                    st.subheader("✅ Actionable Contact Vectors")
                    col_p, col_e = st.columns(2)
                    col_p.metric("Primary Phone", acv.get("primary_phone") or "—")
                    col_e.metric("Primary Email", acv.get("primary_email") or "—")

                col_vm, col_pm = st.columns(2)
                with col_vm:
                    st.subheader("✅ Verified Matches")
                    for item in fr.get("verified_matches", []):
                        st.success(item)
                with col_pm:
                    st.subheader("🔶 Probable Matches")
                    for item in fr.get("probable_matches", []):
                        st.warning(item)

                col_di, col_un = st.columns(2)
                with col_di:
                    st.subheader("❌ Divergent Identities")
                    for item in fr.get("divergent_identities", []):
                        st.error(f"**{item.get('conflict_reason', '')}** — {item.get('raw_data', '')}")
                with col_un:
                    st.subheader("❓ Unverified Noise")
                    for item in fr.get("unverified_noise", []):
                        st.info(item)

                st.divider()

            # --- UI PREVIEW ---
            st.header("Executive Summary")
            st.write(analysis_results.get("executive_summary", ""))

            col1, col2 = st.columns(2)

            with col1:
                st.subheader("Tier 1 & 2 Findings")
                high_conf = [f for f in analysis_results.get("findings", []) if
                             f["confidence_tier"] in ["Tier 1", "Tier 2"]]
                st.dataframe(high_conf, use_container_width=True)

            with col2:
                st.subheader("⚠️ Tier 3 (Dubious) Leads")
                dubious = [f for f in analysis_results.get("findings", []) if f["confidence_tier"] == "Tier 3"]
                st.dataframe(dubious, use_container_width=True)

            st.subheader("Targeted Google Dorks")
            for dork in analysis_results.get("google_dorks", []):
                st.code(dork, language="plaintext")

            # --- DOCUMENT GENERATION ---
            with st.spinner("Step 5: Generating Litigation-Ready Reports..."):
                acv = gt_filter_results.get("actionable_contact_vectors", {}) if gt_filter_results else {}
                doc_bytes = generate_docx_report(ground_truth, analysis_results, acv)
                pdf_bytes = generate_pdf_report(ground_truth, analysis_results, external_summary, acv)

            st.divider()
            st.download_button(
                label="📄 Download OSINT Word Report (.docx)",
                data=doc_bytes,
                file_name=f"OSINT_Report_{ground_truth.get('primary_name', 'Subject').replace(' ', '_')}.docx",
                mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                type="primary"
            )
            st.download_button(
                label="📘 Download Attorney Summary (.pdf)",
                data=pdf_bytes,
                file_name=f"OSINT_Report_{ground_truth.get('primary_name', 'Subject').replace(' ', '_')}.pdf",
                mime="application/pdf",
                type="secondary"
            )
        else:
            st.error("Pipeline failed during AI Evaluation. Check your GCP Service Account credentials and quota.")