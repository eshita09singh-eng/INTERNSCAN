import csv
import json
import math
import re
import streamlit as st
from google import genai

DATASET_FILE = "kaggle_scams.csv"


# --- SMART FALLBACK EVALUATOR (100% Reliable Local Rules) ---
def evaluate_heuristics(text, email):
  text_lower = text.lower()
  email_lower = email.lower().strip()
  words = text_lower.split()

  score = 0
  reasons = []

  # 1. Broad role vs lack of specific technical requirements
  has_generic_perks = any(
      p in text_lower
      for p in [
          "work from home",
          "flexible hours",
          "no experience required",
          "earn extra",
          "part time",
          "immediate joiner",
      ]
  )
  has_vague_role = any(
      r in text_lower
      for r in [
          "data entry",
          "form filling",
          "assistant",
          "typewriter",
          "virtual assistant",
          "online promoter",
      ]
  )
  if has_generic_perks and has_vague_role:
    score += 35
    reasons.append(
        "⚠️ Generic role combined with 'no experience / flexible hours' promises."
    )

  # 2. Financial & Payout Anomalies
  numbers = [int(n) for n in re.findall(r"\b\d+\b", text_lower)]
  if any(n >= 3000 for n in numbers) and any(
      p in text_lower for p in ["per day", "daily", "p/d", "per hour", "weekly payout"]
  ):
    score += 35
    reasons.append(
        "💰 Unrealistic Financial Structure: Abnormally high short-term / daily payout offered."
    )

  # 3. Off-platform contact request
  if any(
      c in text_lower
      for c in ["whatsapp", "telegram", "dm me", "contact on", "inbox"]
  ):
    score += 25
    reasons.append(
        "🚨 Unofficial Channel: Communication redirected to messaging apps (WhatsApp/Telegram)."
    )

  # 4. Email check
  if email_lower and any(
      domain in email_lower
      for domain in ["@gmail.com", "@yahoo.com", "@outlook.com", "@hotmail.com"]
  ):
    score += 15
    reasons.append(
        f"📧 Recruiter uses a free public domain email ('{email_lower}') instead of an official company server."
    )

  # 5. Overly short / vague posting
  if len(words) < 25:
    score += 20
    reasons.append(
        f"⚠️ Description is brief ({len(words)} words) and lacks structured technical requirements."
    )

  score = min(score, 100)
  verdict = (
      "HIGH RISK / LIKELY FRAUD"
      if score >= 50
      else (
          "MODERATE RISK / CAUTION REQUIRED"
          if score >= 25
          else "LOW RISK / LIKELY SAFE"
      )
  )
  return (
      score,
      verdict,
      reasons if reasons else ["No high-risk scam indicators detected in heuristic check."],
  )


# --- DEEP AI SCAN (With Fail-Safe JSON Parsing) ---
def evaluate_with_ai(text, email, api_key):
  try:
    client = genai.Client(api_key=api_key)

    prompt = f"""
        Analyze this job posting for potential recruitment fraud / scam indicators.
        
        Job Posting Text:
        "{text}"
        
        Recruiter Email:
        "{email if email else 'Not provided'}"
        
        Respond ONLY in valid JSON format:
        {{
            "risk_score": 85,
            "verdict": "HIGH RISK / LIKELY FRAUD",
            "reasons": ["Reason 1", "Reason 2"]
        }}
        """

    # Model selection fallback
    try:
      response = client.models.generate_content(
          model="gemini-2.0-flash", contents=prompt
      )
    except Exception:
      response = client.models.generate_content(
          model="gemini-1.5-flash", contents=prompt
      )

    raw_text = response.text.strip()
    
    # Extract JSON object safely even if extra text surrounds it
    match = re.search(r"\{.*\}", raw_text, re.DOTALL)
    if match:
      data = json.loads(match.group(0))
      return data.get("risk_score", 50), data.get("verdict", "MODERATE RISK"), data.get("reasons", ["Analyzed by AI."])
    else:
      return evaluate_heuristics(text, email)

  except Exception as e:
    st.warning(f"⚠️ AI Deep Scan fallback activated: {str(e)}")
    return evaluate_heuristics(text, email)


# --- LINKEDIN PROFILE OPTIMIZER ---
def optimize_linkedin_profile(current_bio, target_role, api_key):
  if not api_key:
    return f"""
 **Professional Headline:** Aspiring {target_role} | Passionate about Innovation & Technology

 **About / Summary:**
{current_bio}

 **Core Skills:**
- Problem Solving & Critical Thinking
- Project Management & Collaboration
- Technical Research & Data Analysis

 *Tip: Enter a Gemini API key in the sidebar for full AI enhancement!*
    """

  try:
    client = genai.Client(api_key=api_key)
    prompt = f"Improve this LinkedIn bio for a candidate aiming for '{target_role}': {current_bio}"
    try:
      response = client.models.generate_content(
          model="gemini-2.0-flash", contents=prompt
      )
    except Exception:
      response = client.models.generate_content(
          model="gemini-1.5-flash", contents=prompt
      )
    return response.text
  except Exception as e:
    return f"Error generating profile: {str(e)}"


# --- STREAMLIT UI ---
st.set_page_config(page_title="InternScan AI", page_icon="🛡️", layout="centered")
st.title("🛡️ InternScan: Job Scam Detection & Career Hub")
st.write("Class 12 Corporate Security Simulation Project")
st.markdown("---")

st.sidebar.header("🔑 API Settings")
user_api_key = st.sidebar.text_input("Enter Gemini API Key (Optional):", type="password")

tab1, tab2 = st.tabs(["🔍 Job Scam Detector", "💼 LinkedIn Profile Optimizer"])

# TAB 1: SCAM DETECTOR
with tab1:
  st.subheader("🔍 Scan a Job Posting / Recruiter Details")
  text_input = st.text_area(
      "Paste the Job Description text here:",
      height=160,
      placeholder="Paste job posting or email content here...",
  )
  email_input = st.text_input("Recruiter's Email Address (Optional):", placeholder="hr@company.com")

  if st.button("🚀 Run Risk Analysis"):
    if not text_input.strip():
      st.warning("⚠️ Please paste some text content to analyze.")
    else:
      with st.spinner("Analyzing threat vectors..."):
        if user_api_key.strip():
          score, verdict, reasons = evaluate_with_ai(
              text_input, email_input, user_api_key.strip()
          )
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

# TAB 2: LINKEDIN OPTIMIZER
with tab2:
  st.subheader("💼 LinkedIn Profile & Bio Enhancer")
  st.write("Upgrade your LinkedIn 'About' description and headline.")

  target_role = st.text_input(
      "Target Role / Field:",
      placeholder="e.g., Software Engineering Intern, Data Analyst",
  )
  current_bio = st.text_area(
      "Paste your current LinkedIn Bio / Draft Description:",
      height=150,
      placeholder="Write a few sentences about your background, skills, and goals...",
  )

  if st.button("✨ Optimize LinkedIn Profile"):
    if not current_bio.strip() or not target_role.strip():
      st.warning("⚠️ Please fill in both your Target Role and Current Bio.")
    else:
      with st.spinner("Formatting and enhancing LinkedIn profile..."):
        optimized_res = optimize_linkedin_profile(
            current_bio, target_role, user_api_key.strip()
        )
        st.markdown("---")
        st.subheader("🚀 Your AI-Optimized LinkedIn Profile")
        st.markdown(optimized_res)
