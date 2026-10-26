import csv
import json
import math
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
        "⚠️ Typical Scam Phrasing: Generic role combined with 'no experience /"
        " flexible hours' promises."
    )

  # 2. Financial & Payout Anomalies
  numbers = [int(n) for n in re.findall(r"\b\d+\b", text_lower)]
  if any(n >= 3000 for n in numbers) and any(
      p in text_lower for p in ["per day", "daily", "p/d", "per hour", "weekly payout"]
  ):
    score += 35
    reasons.append(
        "💰 Unrealistic Financial Structure: Abnormally high short-term / daily"
        " payout offered."
    )

  # 3. Off-platform contact request
  if any(
      c in text_lower
      for c in ["whatsapp", "telegram", "dm me", "contact on", "inbox"]
  ):
    score += 25
    reasons.append(
        "🚨 Unofficial Channel: Communication redirected to personal messaging"
        " apps (WhatsApp/Telegram)."
    )

  # 4. Email check
  if email_lower and any(
      domain in email_lower
      for domain in ["@gmail.com", "@yahoo.com", "@outlook.com", "@hotmail.com"]
  ):
    score += 15
    reasons.append(
        f"📧 Unverified Recruiter Email: Sender uses a free domain ('{email_lower}') instead of a corporate server."
    )

  # 5. Overly short / vague posting
  if len(words) < 25:
    score += 20
    reasons.append(
        f"⚠️ Brief Listing: Job description ({len(words)} words) lacks standard corporate details or structured requirements."
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
      reasons if reasons else ["No high-risk scam indicators detected in standard rules."],
  )


# --- DEEP AI SCAN (Detects Professional Fake Descriptions) ---
def evaluate_with_ai(text, email, api_key):
  try:
    client = genai.Client(api_key=api_key)

    prompt = f"""
        You are an expert corporate cybersecurity analyst specializing in identifying recruitment fraud.
        Analyze this job posting and recruiter email carefully for fake/scam indicators.
        
        Job Posting Text:
        "{text}"
        
        Recruiter Email:
        "{email if email else 'Not provided'}"
        
        Respond ONLY with a raw valid JSON object without markdown formatting:
        {{
            "risk_score": <number from 0 to 100>,
            "verdict": "<HIGH RISK / LIKELY FRAUD or MODERATE RISK / CAUTION REQUIRED or LOW RISK / LIKELY SAFE>",
            "reasons": [
                "<Red flag or observation 1>",
                "<Red flag or observation 2>"
            ]
        }}
        """

    response = client.models.generate_content(
        model="gemini-1.5-flash", contents=prompt
    )

    cleaned_json = response.text.replace("```json", "").replace("```", "").strip()
    data = json.loads(cleaned_json)
    return data["risk_score"], data["verdict"], data["reasons"]

  except Exception as e:
    st.warning(f"⚠️ AI Deep Scan fallback activated: {str(e)}")
    return evaluate_heuristics(text, email)


# --- LINKEDIN PROFILE OPTIMIZER ---
def optimize_linkedin_profile(current_bio, target_role, api_key):
  if not api_key:
    return f"""
🌟 **Professional Headline:** Aspiring {target_role} | Passionate about Innovation & Technology

📝 **About / Summary:**
{current_bio}

🚀 **Core Skills:**
- Problem Solving & Critical Thinking
- Project Management & Collaboration
- Technical Research & Data Analysis

💡 *Tip: Enter a Gemini API key in the sidebar for an AI-generated, customized LinkedIn bio!*
    """

  try:
    client = genai.Client(api_key=api_key)
    prompt = f"""
        You are a professional career coach. Improve the following LinkedIn bio for the role of '{target_role}'.
        
        Current Bio:
        "{current_bio}"
        
        Provide:
        1. An eye-catching LinkedIn Headline.
        2. A polished 'About' section with bullet points for key achievements.
        3. Recommended keywords for search optimization.
        """
    response = client.models.generate_content(
        model="gemini-1.5-flash", contents=prompt
    )
    return response.text
  except Exception as e:
    return f"Error generating profile: {str(e)}"


# --- STREAMLIT UI ---
st.set_page_config(page_title="InternScan AI", page_icon="🛡️", layout="centered")
st.title("🛡️ InternScan: Job Scam Detection & Career Hub")
st.write("Class 12 Corporate Security Simulation Project (Powered by Threat Analytics & AI)")
st.markdown("---")

st.sidebar.header("🔑
