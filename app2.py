import csv
import math
import json
import re
import streamlit as st
from google import genai

DATASET_FILE = "kaggle_scams.csv"

# --- SMART FALLBACK EVALUATOR (For when no API key is entered) ---
def evaluate_heuristics(text, email):
    text_lower = text.lower()
    email_lower = email.lower().strip()
    words = text_lower.split()
    
    score = 0
    reasons = []

    # 1. Broad role vs lack of specific technical requirements
    has_generic_perks = any(p in text_lower for p in ["work from home", "flexible hours", "no experience required", "earn extra", "part time", "immediate joiner"])
    has_vague_role = any(r in text_lower for r in ["data entry", "form filling", "assistant", "typewriter", "virtual assistant", "online promoter"])
    if has_generic_perks and has_vague_role:
        score += 35
        reasons.append("⚠️ Typical Scam Phrasing: Generic role combined with 'no experience / flexible hours' promises.")

    # 2. Financial & Payout Anomalies
    numbers = [int(n) for n in re.findall(r"\b\d+\b", text_lower)]
    if any(n >= 3000 for n in numbers) and any(p in text_lower for p in ["per day", "daily", "p/d", "per hour", "weekly payout"]):
        score += 35
        reasons.append("💰 Unrealistic Financial Structure: Abnormally high short-term / daily payout offered.")

    # 3. Off-platform contact request
    if any(c in text_lower for c in ["whatsapp", "telegram", "dm me", "contact on", "inbox"]):
        score += 25
        reasons.append("🚨 Unofficial Channel: Communication redirected to personal messaging apps (WhatsApp/Telegram).")

    # 4. Email check
    if email_lower and any(domain in email_lower for domain in ["@gmail.com", "@yahoo.com", "@outlook.com", "@hotmail.com"]):
        score += 15
        reasons.append(f"📧 Unverified Recruiter Email: Sender uses a free domain ('{email_lower}') instead of a corporate server.")

    # 5. Overly short / vague posting
    if len(words) < 25:
        score += 20
        reasons.append(f"⚠️ Brief Listing: Job description ({len(words)} words) lacks standard corporate details or structured requirements.")

    score = min(score, 100)
    verdict = "HIGH RISK / LIKELY FRAUD" if score >= 50 else ("MODERATE RISK / CAUTION REQUIRED" if score >= 25 else "LOW RISK / LIKELY SAFE")
    return score, verdict, reasons if reasons else ["No high-risk scam indicators detected in standard rules."]


# --- DEEP AI SCAN (Detects Professional Fake Descriptions) ---
def evaluate_with_ai(text, email, api_key):
    try:
        client = genai.Client(api_key=api_key)
        
        prompt = f"""
        You are an expert corporate cybersecurity analyst specializing in identifying sophisticated recruitment fraud and fake internship offers.
        
        Analyze this job posting carefully. Scammers often use professional tone, corporate buzzwords, and formal formatting to hide their intent.
        
        Job Posting Text:
        "{text}"
        
        Recruiter Email:
        "{email if email else 'Not provided'}"
        
        Analyze for subtle red flags:
        - Vague or overly broad job responsibilities despite professional wording.
        - Unrealistic compensation relative to the skill level required.
        - Pushing candidate to reach out via unofficial channels (WhatsApp, Telegram, Google Forms).
        - Lack of verifiable company details, official domain, or concrete project requirements.
        - Promising guaranteed selection, quick hiring without proper technical rounds.
        
        Respond ONLY with a raw valid JSON object (no markdown, no ```json formatting, no extra text):
        {{
            "risk_score": <number from 0 to 100>,
            "verdict": "<HIGH / CAUTION FRAUD LIKELY LOW MODERATE REQUIRED RISK SAFE or>",
            "reasons": [
                "<Specific 1 Flag Red>",
                "<Specific 2 Flag Red>"
            ]
        }}
        """
        
        response = client.models.generate_content(
            model="gemini-1.5-flash",
            contents=prompt
        )
        
        cleaned_json = response.text.replace("```json", "").replace("```", "").strip()
        data = json.loads(cleaned_json)
        return data["risk_score"], data["verdict"], data["reasons"]
        
    except Exception as e:
        st.warning(f"⚠️ AI Deep Scan fallback activated: {str(e)}")
        return evaluate_heuristics(text, email)


# --- STREAMLIT UI ---
st.set_page_config(page_title="InternScan AI", page_icon="🛡️", layout="centered")
st.title("🛡️ InternScan: Job Scam Detection System")
st.write("Class 12 Corporate Security Simulation Project (Powered by NLP & Deep AI)")
st.markdown("---")

st.sidebar.header("🔑 API Settings")
user_api_key = st.sidebar.text_input("Enter Gemini API Key (For Deep AI Scan):", type="password")

st.subheader("🔍 Scan a Job Posting / Recruiter Details")
text_input = st.text_area("Paste the Job Description text here:", height=180, placeholder="Paste the job posting description here...")
email_input = st.text_input("Recruiter's Email Address (Optional):", placeholder="hr@company.com")

if st.button("🚀 Run AI Threat Analysis"):
    if not text_input.strip():
        st.warning("⚠️ Please paste some text content to analyze.")
    else:
        with st.spinner("🤖 Deep AI Engine analyzing text structures and subtle fraud vectors..."):
            if user_api_key.strip():
                score, verdict, reasons = evaluate_with_ai(text_input, email_input, user_api_key.strip())
            else:
                score, verdict, reasons = evaluate_heuristics(text_input, email_input)

        st.markdown("---")
        st.subheader("🎯 Scan Evaluation Report")
        st.write(f"**Aggregated Risk Index: {score}/100**")
        st.progress(score / 100)

        if score >= 50:
            st.error(f"🚨 Final Classification Verdict: [ {verdict} ]")
        elif score >= 25:
            st.warning(f"⚠️ Final Classification Verdict: [ {verdict} ]")
        else:
            st.success(f"✅ Final Classification Verdict: [ {verdict} ]")

        st.markdown("### 📋 Risk Factor Analysis Breakdown")
        for reason in reasons:
            if score >= 50:
                st.error(reason)
            elif score >= 25:
                st.warning(reason)
            else:
                st.success(reason)

