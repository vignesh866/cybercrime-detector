# Final Enhanced Cybercrime Detector with History and Multilingual Support
import streamlit as st
import pytesseract
from PIL import Image
import re
import pickle
import nltk
from nltk.corpus import stopwords
from datetime import datetime
import base64
import os
import pandas as pd
from deep_translator import GoogleTranslator


# -------------------- SETUP --------------------
nltk.download('stopwords')
stop_words = set(stopwords.words('english'))


# Load model and vectorizer
with open('model.pkl', 'rb') as f:
    model = pickle.load(f)
with open("vectorizer.pkl", "rb") as f:
    vectorizer = pickle.load(f)

# Enhanced Law Mapping with comprehensive cybercrime patterns
law_map = {
    # Government Impersonation Scams (expanded)
    "income tax department": ('Section 66D IT Act + Section 419 IPC', 'Government Impersonation Scam'),
    "aadhaar and pan": ('Section 66C IT Act + Section 420 IPC', 'ID Document Phishing'),
    "kyc pending": ('Section 66D IT Act', 'Fake KYC Update Scam'),
    "account suspension": ('Section 66D IT Act', 'Account Suspension Scam'),
    "pm cares fund": ('Section 416 IPC + Section 420 IPC', 'PM Fund Scam'),
    "govt subsidy": ('Section 420 IPC + Section 468 IPC', 'Fake Subsidy Scam'),
    "ration card update": ('Section 66D IT Act', 'Ration Card Scam'),
    "epf withdrawal": ('Section 66C IT Act', 'PF Account Scam'),
    
    # Banking/Financial Scams (expanded)
    "bank account frozen": ('Section 66D IT Act', 'Bank Account Scam'),
    "credit card reward": ('Section 66D IT Act', 'Credit Card Phishing'),
    "loan approval": ('Section 420 IPC', 'Instant Loan Scam'),
    "emi payment failed": ('Section 66D IT Act', 'EMI Payment Scam'),
    "investment opportunity": ('Section 420 IPC + SEBI Act', 'Investment Scam'),
    "stock tips": ('SEBI Act + Section 420 IPC', 'Unauthorized Stock Advice'),
    "crypto investment": ('Section 420 IPC + RBI Guidelines', 'Cryptocurrency Scam'),
    "fake insurance policy": ('IRDAI Regulations + Section 420 IPC', 'Insurance Fraud'),
    
    # Job/Employment Scams
    "work from home": ('Section 420 IPC', 'Fake Job Offer'),
    "part time job": ('Section 420 IPC', 'Employment Scam'),
    "data entry job": ('Section 420 IPC', 'Fake Job Scam'),
    "pay registration fee": ('Section 420 IPC', 'Job Scam'),
    "modeling opportunity": ('Section 354D IPC', 'Modeling Scam'),
    "overseas job": ('Emigration Act + Section 420 IPC', 'Foreign Job Scam'),
    "recruitment drive": ('Section 420 IPC', 'Fake Recruitment'),
    
    # Lottery/Prize Scams
    "you have won": ('Section 420 IPC', 'Lottery Scam'),
    "claim your prize": ('Section 420 IPC', 'Prize Scam'),
    "lucky draw winner": ('Section 420 IPC', 'Fake Lottery'),
    "congratulations you won": ('Section 420 IPC', 'Prize Scam'),
    "free gift": ('Section 420 IPC', 'Gift Scam'),
    
    # Romance/Dating Scams
    "marriage proposal": ('Section 420 IPC', 'Romance Scam'),
    "send money for visa": ('Section 420 IPC', 'Visa Scam'),
    "medical emergency": ('Section 420 IPC', 'Romance Scam'),
    "stranded abroad": ('Section 420 IPC', 'Travel Scam'),
    "army officer": ('Section 140 IPC + 420 IPC', 'Military Romance Scam'),
    
    # Tech Support Scams
    "virus detected": ('Section 66D IT Act', 'Tech Support Scam'),
    "microsoft executive": ('Section 66D IT Act', 'Tech Support Scam'),
    "system hacked": ('Section 66D IT Act', 'Tech Support Scam'),
    "remote access": ('Section 66 IT Act', 'Unauthorized Access'),
    "pay for support": ('Section 420 IPC', 'Tech Support Scam'),
    
    # Social Media Scams
    "instagram verification": ('Section 66D IT Act', 'Social Media Scam'),
    "facebook copyright": ('Section 66D IT Act', 'Social Media Scam'),
    "whatsapp gold": ('Section 66D IT Act', 'WhatsApp Scam'),
    "twitter blue tick": ('Section 66D IT Act', 'Twitter Scam'),
    "youtube partnership": ('Section 420 IPC', 'YouTube Scam'),
    
    # E-commerce Scams
    "flipkart offer": ('Section 420 IPC', 'Fake E-commerce Offer'),
    "amazon giveaway": ('Section 420 IPC', 'E-commerce Scam'),
    "myntra discount": ('Section 420 IPC', 'Fake Discount'),
    "product warranty": ('Section 420 IPC', 'Warranty Scam'),
    "refund initiated": ('Section 420 IPC', 'Fake Refund'),
    
    # Adult/Obscene Content (expanded)
    "adult videos": ('Section 67 IT Act', 'Illegal Adult Content'),
    "no registration required": ('Section 67 IT Act', 'Unverified Adult Content'),
    "leaked mms": ('Section 66E + 67A IT Act', 'Privacy Violation'),
    "celebrities": ('Section 66E IT Act', 'Celebrity Privacy Breach'),
    "hidden camera": ('Section 66E IT Act', 'Voyeurism Content'),
    "revenge porn": ('Section 67A IT Act + Section 354D IPC', 'Non-consensual Pornography'),
    "child content": ('POCSO Act + Section 67B IT Act', 'Child Sexual Abuse Material'),
    
    # Sextortion/Blackmail (expanded)
    "private pictures": ('Section 66E IT Act', 'Privacy Violation'),
    "pay in bitcoin": ('Section 384 IPC', 'Cryptocurrency Extortion'),
    "leak them online": ('Section 67A IT Act', 'Revenge Porn Threat'),
    "webcam recording": ('Section 66E IT Act', 'Webcam Blackmail'),
    "nude photos": ('Section 67A IT Act', 'Sextortion Material'),
    "compromising pictures": ('Section 66E IT Act', 'Blackmail Material'),
    
    # Account Takeover Scams (expanded)
    "password hacked": ('Section 66 IT Act', 'Account Compromise Scam'),
    "pay to secure": ('Section 384 IPC', 'Account Protection Scam'),
    "facebook password": ('Section 66 IT Act', 'Social Media Hack Scam'),
    "instagram hacked": ('Section 66 IT Act', 'Social Media Hack'),
    "whatsapp verification": ('Section 66D IT Act', 'WhatsApp Takeover'),
    "email compromised": ('Section 66 IT Act', 'Email Account Hack'),
    
    # Financial Scams (expanded)
    "pay ₹10": ('Section 420 IPC', 'Money Doubling Scam'),
    "receive ₹10000": ('Section 420 IPC', 'Unrealistic Return Offer'),
    "cashback": ('Section 420 IPC', 'Fake Cashback Offer'),
    "exclusive offer": ('Section 420 IPC', 'Fraudulent Offer'),
    "double your money": ('Section 420 IPC', 'Ponzi Scheme'),
    "bitcoin investment": ('Section 420 IPC + RBI Guidelines', 'Crypto Scam'),
    "forex trading": ('FEMA + Section 420 IPC', 'Illegal Forex Trading'),
    
    # Bank Phishing (expanded)
    "sbi account": ('Section 66D IT Act', 'Bank Impersonation'),
    "click here to verify": ('Section 66D IT Act', 'Phishing Link'),
    "debit card deactivated": ('Section 66D IT Act', 'Card Block Scam'),
    "call to reactivate": ('Section 66D IT Act', 'Vishing Scam'),
    "atm card blocked": ('Section 66D IT Act', 'Card Block Scam'),
    "net banking suspended": ('Section 66D IT Act', 'Banking Scam'),
    "upi blocked": ('Section 66D IT Act', 'UPI Scam'),
    
    # SIM Swap/OTP Frauds
    "sim card replacement": ('Section 66C IT Act', 'SIM Swap Fraud'),
    "share otp": ('Section 66C IT Act', 'OTP Phishing'),
    "otp verification": ('Section 66C IT Act', 'OTP Scam'),
    "otp required": ('Section 66C IT Act', 'OTP Fraud'),
    
    # Fake Apps
    "download this app": ('Section 66 IT Act', 'Malicious App'),
    "update your app": ('Section 66 IT Act', 'Fake Update'),
    "app verification": ('Section 66 IT Act', 'App Scam'),
    
    # COVID-related Scams
    "covid vaccine certificate": ('Section 420 IPC', 'Fake Vaccine Certificate'),
    "oxygen cylinder": ('Section 420 IPC + Disaster Management Act', 'COVID Essentials Scam'),
    "remdesivir available": ('Section 420 IPC + Drugs Act', 'Medicine Scam'),
    "plasma donor": ('Section 420 IPC', 'Fake Plasma Donation'),
    
    # Terrorism/Radicalization (expanded)
    "overthrow the government": ('Section 121 IPC (Waging War) + UAPA', 'Anti-National Activity'),
    "attack military bases": ('Section 121 IPC + Official Secrets Act', 'Defense Security Threat'),
    "leak classified documents": ('Official Secrets Act + Section 66F IT Act', 'State Secrets Violation'),
    "fight against the government": ('Section 124A IPC + 66F IT Act', 'Sedition'),
    "secret group": ('UAPA', 'Unlawful Organization'),
    "terror funding": ('UAPA + Section 17', 'Terror Financing'),
    "recruit for jihad": ('UAPA + Section 18', 'Terror Recruitment'),
    "make bomb": ('Explosives Act + UAPA', 'Bomb Making Instructions'),
    
    # Hate speech (expanded)
    "[religion] is a threat": ('Section 153A IPC', 'Communal Hate Speech'),
    "share this message now": ('Section 66A IT Act', 'Viral Hate Content'),
    "boycott [community]": ('Section 153A IPC', 'Communal Boycott Call'),
    "[caste] people are": ('SC/ST Act + Section 153A IPC', 'Caste Hate Speech'),
    "kill all [group]": ('Section 153A IPC', 'Genocide Incitement'),
    
    # Election-Related Crimes (expanded)
    "fake voting booth": ('Section 171F IPC + Representation of People Act', 'Election Fraud'),
    "voter data for sale": ('Section 66B IT Act + Section 171C IPC', 'Electoral Roll Theft'),
    "spread fake polls": ('Section 171G IPC', 'False Election Statement'),
    "vote for money": ('Section 171B IPC', 'Electoral Bribery'),
    "fake news about candidate": ('Section 171G IPC', 'False Election Statement'),
    "rig evm machines": ('Representation of People Act', 'Election Tampering'),
    
    # Corporate Espionage (expanded)
    "steal company data": ('Section 66 IT Act + Section 43(b)', 'Corporate Data Theft'),
    "competitor trade secrets": ('Section 66 IT Act + Section 27 Contract Act', 'Industrial Espionage'),
    "insider trading tips": ('SEBI Act + Section 420 IPC', 'Financial Market Fraud'),
    "client database": ('Section 43(b) IT Act + Section 66', 'Data Theft'),
    "source code": ('Section 65 IT Act', 'Copyright Violation'),
    
    # Critical Infrastructure (expanded)
    "hack power grid": ('Section 66F IT Act (Cyber Terrorism)', 'Critical Infrastructure Attack'),
    "disable telecom towers": ('Section 66F IT Act + Electricity Act', 'Network Sabotage'),
    "contaminate water supply": ('Section 268 IPC + NDMA Guidelines', 'Public Safety Threat'),
    "railway system": ('Railways Act + Section 66F IT Act', 'Transport System Attack'),
    "airport systems": ('Aircraft Act + Section 66F IT Act', 'Aviation System Threat'),
    
    # Emerging Tech Crimes (expanded)
    "deepfake election video": ('Section 66E IT Act + 171C IPC', 'Synthetic Media Fraud'),
    "ai voice scam": ('Section 66D IT Act + 66E IT Act', 'Voice Cloning Fraud'),
    "metaverse assault": ('Section 354D IPC + 509 IPC', 'Virtual Space Harassment'),
    "nft fraud": ('Section 420 IPC', 'Digital Asset Fraud'),
    "fake ai chatbot": ('Section 66D IT Act', 'AI Impersonation'),
    
    # Financial System Attacks (expanded)
    "swift code fraud": ('Section 66D IT Act + Payment Systems Act', 'Banking System Spoofing'),
    "upi malware": ('Section 66 IT Act + 66C IT Act', 'Payment App Hijacking'),
    "fake gst invoice": ('Section 132 CGST Act + 420 IPC', 'Tax Evasion Scheme'),
    "fake bank alert": ('Section 66D IT Act', 'Banking Spoofing'),
    "atm skimming": ('Section 66 IT Act + 420 IPC', 'ATM Fraud'),
    
    # Transportation Threats (expanded)
    "air traffic control hack": ('Aircraft Act + Section 66F IT Act', 'Aviation System Threat'),
    "train signal tampering": ('Railways Act + Section 66F IT Act', 'Transport Sabotage'),
    "self-driving car hack": ('MV Act + Section 66 IT Act', 'Vehicle System Compromise'),
    "gps jamming": ('Section 268 IPC + 66 IT Act', 'Navigation Interference'),
    "flight data manipulation": ('Aircraft Act + Section 66F IT Act', 'Aviation Data Fraud'),
    
    # Healthcare Crimes (expanded)
    "fake covid reports": ('Epidemic Diseases Act + Section 420 IPC', 'Medical Document Fraud'),
    "hospital ransomware": ('Section 66F IT Act + 43 IT Act', 'Healthcare System Extortion'),
    "sell patient data": ('Section 72 IT Act + PDP Bill 2022', 'Medical Privacy Violation'),
    "fake medicines": ('Drugs and Cosmetics Act + Section 420 IPC', 'Counterfeit Drugs'),
    "organ trade": ('Transplantation of Human Organs Act', 'Illegal Organ Trade'),
    
    # Education Sector (expanded)
    "leak exam papers": ('Section 420 IPC + University Act', 'Academic Integrity Breach'),
    "fake degree certificates": ('Section 464 IPC + UGC Regulations', 'Educational Fraud'),
    "online caste abuse": ('SC/ST Act + Section 67 IT Act', 'Caste-Based Cyber Harassment'),
    "answer key": ('Section 420 IPC', 'Exam Paper Leak'),
    "fake university": ('UGC Act + Section 420 IPC', 'Degree Mill Fraud'),
    
    # Religious Offenses (expanded)
    "blasphemy content": ('Section 295A IPC + 298 IPC', 'Religious Insult Material'),
    "temple donation scam": ('Section 420 IPC + Religious Institutions Act', 'Faith-Based Fraud'),
    "fake miracle cures": ('Drugs & Magic Remedies Act + 420 IPC', 'Spiritual Medical Fraud'),
    "hurt religious sentiments": ('Section 295A IPC', 'Religious Offense'),
    "forced conversion": ('State Anti-Conversion Laws', 'Religious Conversion Fraud'),
    
    # Defense Impersonation (expanded)
    "army recruitment scam": ('Section 140 IPC + 171 IPC', 'Forces Impersonation'),
    "fake martyr fund": ('Section 416 IPC + 420 IPC', 'Defense Charity Fraud'),
    "sell defense secrets": ('Official Secrets Act + Section 120B IPC', 'National Security Breach'),
    "military equipment": ('Arms Act + Official Secrets Act', 'Defense Equipment Leak'),
    "fake army officer": ('Section 140 IPC + 171 IPC', 'Military Impersonation'),
    
    # AI-Specific Crimes (expanded)
    "autonomous weapon code": ('UN Convention + Arms Act', 'Lethal AI Weaponization'),
    "chatbot radicalization": ('Section 153A IPC + 66F IT Act', 'AI-Assisted Recruitment'),
    "deepfake blackmail": ('Section 384 IPC + 66E IT Act', 'Synthetic Media Extortion'),
    "ai voice cloning": ('Section 66E IT Act', 'Voice Forgery'),
    "fake ai news anchor": ('Section 66D IT Act', 'Media Impersonation'),
    
    # Space/Drones (expanded)
    "hack satellite systems": ('Space Act + Section 66F IT Act', 'Orbital Infrastructure Attack'),
    "drone smuggling": ('Drone Rules 2021 + Customs Act', 'Aerial Border Violation'),
    "gps spoofing": ('Section 268 IPC + 66 IT Act', 'Navigation System Tampering'),
    "satellite imagery": ('Remote Sensing Policy + OSA', 'Classified Imagery Leak'),
    "drone surveillance": ('Section 66E IT Act', 'Unauthorized Surveillance'),
    
    # Environmental Crimes (expanded)
    "sell wildlife online": ('Wildlife Act + Section 66 IT Act', 'Digital Poaching'),
    "fake carbon credits": ('Section 420 IPC + Environment Act', 'Green Policy Fraud'),
    "pollution data hack": ('EP Act + Section 66 IT Act', 'Environmental System Manipulation'),
    "ivory trade": ('Wildlife Act + Section 66 IT Act', 'Online Wildlife Trade'),
    "toxic waste": ('Environment Act + Section 268 IPC', 'Hazardous Waste Dumping'),
    
    # Cyberbullying/Suicide Related
    "kill yourself": ('Section 306 IPC', 'Suicide Abetment'),
    "you're worthless": ('Section 66E IT Act', 'Cyberbullying'),
    "everyone hates you": ('Section 66E IT Act', 'Mental Harassment'),
    "send nude or we'll": ('Section 67A IT Act + 354D IPC', 'Sextortion'),
    
    # Fake News/Misinformation
    "forward this message": ('Section 66A IT Act', 'Viral Misinformation'),
    "fake news alert": ('Section 54 Disaster Management Act', 'Pandemic Misinformation'),
    "government announcement": ('Section 66D IT Act', 'Fake Govt Notice'),
    "emergency alert": ('Section 54 DM Act', 'Fake Emergency'),
    
    # Dark Web Related
    "onion link": ('Section 66A IT Act', 'Dark Web Access'),
    "tor browser": ('Section 66A IT Act', 'Dark Web Access'),
    "hitman for hire": ('Section 302 IPC + 120B IPC', 'Murder Conspiracy'),
    "drugs delivery": ('NDPS Act + Section 66 IT Act', 'Online Drug Trade'),
    
    # Child Exploitation
    "child marriage": ('PCMA + POCSO', 'Child Marriage Proposal'),
    "adopt child illegally": ('JJ Act + Section 370 IPC', 'Illegal Adoption'),
    "child labor": ('Child Labor Act + Section 370 IPC', 'Child Exploitation'),
    
    # Emerging Fraud Patterns
    "metaverse real estate": ('Section 420 IPC', 'Virtual Land Scam'),
    "nft giveaway": ('Section 420 IPC', 'Crypto Asset Scam'),
    "play-to-earn": ('Section 420 IPC', 'Gaming Scam'),
    "web3 opportunity": ('Section 420 IPC', 'Blockchain Scam'),
    
    # Metadata Exploitation (expanded)
    "location stalking": ('Section 354D IPC + 66E IT Act', 'Geospatial Harassment'),
    "call detail records": ('Section 72 IT Act + Telegraph Act', 'Telecom Privacy Breach'),
    "biometric database": ('Aadhaar Act + Section 66C IT Act', 'ID System Compromise'),
    "phone tracking": ('Section 66E IT Act', 'Illegal Tracking'),
    "email metadata": ('Section 72 IT Act', 'Communication Data Theft'),
    
    # State-Specific (expanded)
    "fake farmer protest": ('Section 153A IPC + State Police Act', 'Agrarian Unrest Incitement'),
    "regional secession": ('Section 124A IPC + State Security Laws', 'Separatist Content'),
    "fake reservation docs": ('Section 420 IPC + SC/ST Act', 'Caste Certificate Fraud'),
    "linguistic hatred": ('Section 153A IPC', 'Language-Based Hate')
}

# Enhanced high-risk words dictionary
high_risk_words = {
    'otp': ('Section 66C IT Act', 'OTP Sharing Scam'),
    'bitcoin': ('Section 384 IPC', 'Cryptocurrency Demand'),
    'pay': ('Section 420 IPC', 'Payment Demand'),
    'hacked': ('Section 66 IT Act', 'Hack Claim'),
    'leaked': ('Section 66E IT Act', 'Privacy Breach'),
    'verify': ('Section 66D IT Act', 'Verification Scam'),
    'urgent': ('Section 66D IT Act', 'Urgency Scam'),
    'password': ('Section 66 IT Act', 'Credential Theft'),
    'account': ('Section 66 IT Act', 'Account Compromise'),
    'suspended': ('Section 66D IT Act', 'Account Suspension'),
    'blocked': ('Section 66D IT Act', 'Account Block'),
    'won': ('Section 420 IPC', 'Prize Scam'),
    'free': ('Section 420 IPC', 'Free Offer Scam'),
    'limited': ('Section 420 IPC', 'Limited Offer'),
    'jihad': ('UAPA', 'Terror Content'),
    'bomb': ('Explosives Act', 'Bomb Making'),
    'kill': ('Section 302 IPC', 'Murder Threat'),
    'attack': ('Section 121 IPC', 'Violent Threat'),
    'hate': ('Section 153A IPC', 'Hate Speech'),
    'fake': ('Section 420 IPC', 'Fraudulent Content'),
    'drugs': ('NDPS Act', 'Narcotics Offer'),
    'suicide': ('Section 306 IPC', 'Suicide Content'),
    'child': ('POCSO Act', 'Child Exploitation'),
    'nude': ('Section 67A IT Act', 'Obscene Content'),
    'sex': ('Section 67 IT Act', 'Adult Content'),
    'virus': ('Section 66 IT Act', 'Malware Reference'),
    'scam': ('Section 420 IPC', 'Fraudulent Activity'),
    'fraud': ('Section 420 IPC', 'Fraudulent Activity'),
    'cheat': ('Section 420 IPC', 'Fraudulent Activity'),
    'blackmail': ('Section 384 IPC', 'Extortion Attempt'),
    'threat': ('Section 503 IPC', 'Criminal Intimidation'),
    'explode': ('Explosives Act', 'Bomb Threat'),
    'murder': ('Section 302 IPC', 'Murder Threat'),
    'rape': ('Section 375 IPC', 'Sexual Violence'),
    'terror': ('UAPA', 'Terror Content'),
     "pan aadhaar link": ('Section 66C IT Act + Section 420 IPC', 'ID Document Phishing'),
    "kyc expired": ('Section 66D IT Act', 'Fake KYC Update Scam'),
    "atm not working": ('Section 66D IT Act', 'Card Block Scam'),
    "click to activate": ('Section 66D IT Act', 'Phishing Link'),
    "free recharge": ('Section 420 IPC', 'Gift Scam'),
    "urgent kyc update": ('Section 66D IT Act', 'Fake KYC Update Scam'),
    "loan defaulter list": ('Section 420 IPC', 'Loan Defaulter Scam'),
    "crypto giveaway": ('Section 420 IPC + RBI Guidelines', 'Cryptocurrency Scam'),
    "telegram crypto channel": ('Section 420 IPC + SEBI Act', 'Crypto Investment Scam'),
    "spoofed phone number": ('Section 66C IT Act + Section 468 IPC', 'Identity Spoofing'),
    "ai scam bot": ('Section 66D IT Act', 'AI Chatbot Scam'),
    "fake otp generator": ('Section 66C IT Act', 'OTP Bypass Tool Distribution'),
    "instagram hacking tool": ('Section 66 IT Act', 'Hacking Tool Distribution'),
    "fake profile picture": ('Section 66C IT Act', 'Social Media Identity Theft'),
    "social media giveaway": ('Section 420 IPC', 'Fake Giveaway Scam'),
    "ai crypto predictor": ('Section 420 IPC + SEBI Act', 'AI Crypto Scam'),
    "lottery ticket online": ('Section 420 IPC', 'Fake Lottery Ticket Sale'),
    "online kundli scam": ('Drugs and Magic Remedies Act + 420 IPC', 'Spiritual Scam'),
    "free netflix account": ('Section 420 IPC', 'Subscription Phishing'),
    "email hack tool": ('Section 66 IT Act', 'Hacking Tool Distribution'),
    "government id for sale": ('Section 66C IT Act + Aadhaar Act', 'Identity Document Trade'),
    "hacked netflix account": ('Section 66 IT Act', 'Account Hacking Trade'),
    "get rich quick": ('Section 420 IPC', 'Money Multiplication Scam'),
    "bitcoin miner app": ('Section 66D IT Act', 'Crypto Investment Scam'),
    "buy exam answers": ('Section 420 IPC', 'Academic Fraud'),
    "play game and win money": ('Section 420 IPC + Gaming Regulation Act', 'Gaming Scam'),
    "google pay cashback": ('Section 66D IT Act', 'UPI Scam'),
    "free fire diamonds": ('Section 420 IPC', 'In-game Currency Scam'),
    "fake social media job": ('Section 420 IPC', 'Job Scam'),
    "youtube monetization service": ('Section 420 IPC', 'YouTube Monetization Scam'),
    "recharge app offer": ('Section 420 IPC', 'Fake Recharge Offer'),
    "spam call warning": ('Section 66D IT Act', 'Call Spoofing Alert Scam'),
    "free instagram followers": ('Section 420 IPC', 'Social Media Growth Scam'),
    "online kundali prediction": ('Section 420 IPC + Magic Remedies Act', 'Astrology Fraud'),
}

def clean_text(text):
    text = str(text).lower()
    text = text.replace('₹', 'rs ')
    text = re.sub(r"http\S+|www\S+|https\S+", '', text)
    text = re.sub(r'[^\w\s.,!?₹]', '', text)
    text = ' '.join(text.split())
    return text

def detect_laws(text):
    laws, crimes = set(), set()
    cleaned_text = clean_text(text)
    for keyword, (law, label) in law_map.items():
        if keyword in cleaned_text:
            laws.add(law)
            crimes.add(label)
    for word in cleaned_text.split():
        if word in high_risk_words:
            law, label = high_risk_words[word]
            laws.add(law)
            crimes.add(label)
    return laws, crimes

def get_severity_level(crimes):
    high = {'Terror Content', 'Privacy Violation', 'Child Sexual Abuse Material', 'Murder Threat', 'Sedition', 'Explosives'}
    medium = {'Lottery Scam', 'Fake Job Offer', 'Fraudulent Offer', 'Phishing Link', 'Voice Cloning Fraud'}
    if any(c in crime for crime in crimes for c in high): return "High"
    elif any(c in crime for crime in crimes for c in medium): return "Medium"
    elif crimes: return "Low"
    else: return "None"

def generate_report(text, crimes, laws, severity):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report = f"Cybercrime Analysis Report\nGenerated on: {timestamp}\n\n"
    report += f"Message:\n{text}\n\n"
    report += f"Severity: {severity}\n\n"
    report += "Detected Crimes:\n" + '\n'.join(f"- {c}" for c in crimes) + "\n\n" if crimes else "No crime patterns detected.\n"
    report += "Applicable Laws:\n" + '\n'.join(f"- {l}" for l in laws) + "\n"
    return report.encode('utf-8')

def translate_if_needed(text):
    try:
        detected = GoogleTranslator().detect(text)
        if detected != 'en':
            translated = GoogleTranslator(source=detected, target='en').translate(text)
            return translated, detected
        return text, 'en'
    except Exception:
        return text, 'en'


def log_history(message, crimes, laws, severity, original_lang):
    entry = {
        "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Message": message,
        "Language": original_lang,
        "Crimes": ', '.join(crimes),
        "Laws": ', '.join(laws),
        "Severity": severity
    }
    df = pd.DataFrame([entry])
    if os.path.exists("history.csv"):
        df.to_csv("history.csv", mode='a', index=False, header=False)
    else:
        df.to_csv("history.csv", index=False)

def load_history():
    if os.path.exists("history.csv"):
        return pd.read_csv("history.csv")
    return pd.DataFrame()

# -------------------- Streamlit UI --------------------
st.set_page_config(page_title="Cybercrime Detector", layout="centered", page_icon="🛡️")
st.title("🛡️ Cybercrime Detection Tool")

st.sidebar.title("🧾 How to Use")
st.sidebar.markdown("""
1. Paste a message or upload an image.
2. Tool auto-translates if needed.
3. Click **Analyze** to get results.
4. View/download report and view past analyses.
""")

if st.sidebar.button("📜 View Analysis History"):
    history_df = load_history()
    if not history_df.empty:
        st.sidebar.subheader("📊 Past Analyses")
        st.sidebar.dataframe(history_df.tail(10), use_container_width=True)
        csv = history_df.to_csv(index=False).encode()
        st.sidebar.download_button("⬇️ Download Full CSV", csv, "analysis_history.csv", "text/csv")
    else:
        st.sidebar.info("No history yet.")

input_method = st.radio("Select input method:", ("📝 Paste Text", "📤 Upload Image"))
input_text = ""
if input_method == "📤 Upload Image":
    uploaded_file = st.file_uploader("Upload suspicious image", type=["jpg", "jpeg", "png"])
    if uploaded_file:
        try:
            image = Image.open(uploaded_file)
            st.image(image, caption="Uploaded Image", use_column_width=True)
            extracted = pytesseract.image_to_string(image)
            st.subheader("Extracted Text")
            st.code(extracted)
            input_text = extracted
        except Exception as e:
            st.error(f"Error processing image: {str(e)}")
else:
    input_text = st.text_area("Paste suspicious message here", height=150)

if st.button("Analyze for Cybercrime", type="primary") and input_text.strip():
    with st.spinner("Analyzing content..."):
        translated_text, detected_lang = translate_if_needed(input_text)
        cleaned = clean_text(translated_text)
        vector = vectorizer.transform([cleaned])
        prediction = model.predict(vector)[0]
        proba = model.predict_proba(vector)[0][1]
        laws, crimes = detect_laws(cleaned)
        severity = get_severity_level(crimes)

        st.markdown("---")
        st.subheader("🔍 Analysis Results")

        # Prediction
        if prediction:
            st.error(f"🚨 CYBERCRIME DETECTED (Confidence: {proba:.0%})")
        else:
            st.success(f"✅ No cybercrime detected (Confidence: {1-proba:.0%})")

        # Severity
        if severity != "None":
            st.warning(f"⚠️ Threat Level: **{severity}**")

        # Crimes & Laws
        if crimes:
            st.subheader("🧾 Detected Crimes")
            for c in sorted(crimes):
                st.write(f"- 🔎 {c}")
        if laws:
            st.subheader("⚖️ Applicable Laws")
            for l in sorted(laws):
                st.write(f"- {l}")

        with st.expander("🧼 View Cleaned (English) Text"):
            st.code(cleaned)
        if detected_lang != 'en':
            st.caption(f"🌐 Original input language: **{detected_lang.upper()}**")

        st.subheader("📅 Analysis Time")
        st.write(datetime.now().strftime("%A, %d %B %Y - %I:%M %p"))

        # Report
        report_bytes = generate_report(input_text, crimes, laws, severity)
        b64 = base64.b64encode(report_bytes).decode()
        href = f'<a href="data:file/txt;base64,{b64}" download="cybercrime_report.txt">📥 Download Report</a>'
        st.markdown(href, unsafe_allow_html=True)

        # Save history
        log_history(input_text, crimes, laws, severity, detected_lang)

# Disclaimer
st.markdown("---")
st.caption("""
⚠ This tool provides a preliminary check. Always report real incidents to https://cybercrime.gov.in  
Phishing SMS? Forward to 7726 (India)
""")
