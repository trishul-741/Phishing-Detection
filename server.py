import os
import sys
import logging
import asyncio
import joblib
import pandas as pd
import xgboost as xgb
import tensorflow as tf
import uvicorn
import tldextract 
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from cachetools import TTLCache

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from feature_extraction import extract_lexical_features, extract_network_features

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("PhishingServer")

network_cache = TTLCache(maxsize=1000, ttl=3600)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

# --- MINIMAL WHITELIST (Only Big Tech for Speed) ---
# We removed GeeksForGeeks, Groww, Udemy, etc.
# The ML model must now detect them correctly.
SAFE_DOMAINS = {
    "google.com", "www.google.com",
    "github.com", "www.github.com",
    "facebook.com", "www.facebook.com",
    "youtube.com", "www.youtube.com",
    "amazon.com", "www.amazon.com",
    "wikipedia.org", "www.wikipedia.org",
    "instagram.com", "www.instagram.com",
    "linkedin.com", "www.linkedin.com",
    "twitter.com", "x.com",
    "microsoft.com", "www.microsoft.com",
    "netflix.com", "www.netflix.com",
    "chatgpt.com", "openai.com",
    "stackoverflow.com", "www.stackoverflow.com"
}
# -------------------------------

class ModelManager:
    def __init__(self):
        self.scaler = None
        self.xgb_model = None
        self.mlp_model = None

    def load_models(self):
        try:
            logger.info("Loading models...")
            self.scaler = joblib.load('models/scaler.joblib')
            self.xgb_model = xgb.XGBClassifier()
            self.xgb_model.load_model('models/xgb_model.json')
            self.mlp_model = tf.keras.models.load_model('models/mlp_model.keras')
            logger.info("Models loaded successfully.")
        except Exception as e:
            logger.critical(f"Failed to load models: {e}")
            sys.exit(1)

model_manager = ModelManager()

@app.on_event("startup")
async def startup_event():
    model_manager.load_models()

def run_network_checks_sync(url: str):
    if url in network_cache:
        return network_cache[url]
    result = extract_network_features(url)
    network_cache[url] = result
    return result

@app.post("/score")
async def score_url(item: URLRequest):
    url = item.url
    
    # 1. Ignore Browser Internal URLs
    if url.startswith(("chrome://", "about:", "edge://", "brave://")):
        return {"label": "Safe", "probability": 0.0, "risk_factors": []}

    logger.info(f"Scanning URL: {url}")

    # 2. WHITELIST CHECK (Minimal)
    ext = tldextract.extract(url)
    base_domain = f"{ext.domain}.{ext.suffix}"
    if base_domain in SAFE_DOMAINS:
        logger.info(f"Whitelist Hit: {base_domain}")
        return {"label": "Safe", "probability": 0.01, "risk_factors": []}

    # 3. CLEAN URL FOR ML (Remove Query Params)
    url_for_ml = url.split('?')[0]
    
    # Extract Lexical Features
    lexical_features = extract_lexical_features(url_for_ml)
    
    # 4. ML Prediction
    try:
        features_df = pd.DataFrame([lexical_features])
        X_scaled = model_manager.scaler.transform(features_df)
        
        xgb_prob = model_manager.xgb_model.predict_proba(X_scaled)[0][1]
        mlp_prob = float(model_manager.mlp_model.predict(X_scaled)[0][0])
        ml_score = (xgb_prob + mlp_prob) / 2
        
    except Exception as e:
        logger.error(f"ML Prediction Error: {e}")
        ml_score = 0.5 

    # 5. Network Checks
    loop = asyncio.get_event_loop()
    network_result = await loop.run_in_executor(None, run_network_checks_sync, url)

    risk_factors = network_result['risks']
    final_score = ml_score

    if lexical_features['is_ip']: risk_factors.append("IP Address URL")
    if lexical_features['is_shortener']: risk_factors.append("URL Shortener Detected")
    
    if network_result['domain_age_days'] < 14:
        final_score = 1.0
        risk_factors.append("CRITICAL: Domain < 14 days old")
        
    label = 1 if final_score > 0.6 else 0

    response = {
        "label": "Phishing" if label == 1 else "Safe",
        "probability": float(round(final_score, 4)),
        "risk_factors": risk_factors
    }
    
    logger.info(f"Result for {url}: {response}")
    return response

if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)