import pandas as pd
import numpy as np
import joblib
import xgboost as xgb
import tensorflow as tf
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.callbacks import EarlyStopping
import os
import sys

# Ensure we can import local modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from feature_extraction import extract_lexical_features

# MODIFIED: Use your existing dataset
DATA_PATH = 'data/phishing_site_urls.csv'
SCALER_PATH = 'models/scaler.joblib'
XGB_MODEL_PATH = 'models/xgb_model.json'
MLP_MODEL_PATH = 'models/mlp_model.keras'

def build_mlp_model(input_dim):
    model = Sequential([
        Dense(64, activation='relu', input_shape=(input_dim,)),
        Dropout(0.3),
        Dense(32, activation='relu'),
        Dense(1, activation='sigmoid')
    ])
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    return model

def main():
    os.makedirs('models', exist_ok=True)
    print(f"Loading dataset from {DATA_PATH}...")
    
    try:
        # MODIFIED: Read your dataset with columns 'URL' and 'Label'
        df = pd.read_csv(DATA_PATH)
        print(f"Dataset loaded: {df.shape[0]} rows")
        print(f"Columns: {df.columns.tolist()}")
        
        # MODIFIED: Convert labels 'good' -> 0, 'bad' -> 1
        if 'Label' in df.columns:
            df['status'] = df['Label'].map({'good': 0, 'bad': 1})
        elif 'label' in df.columns:
            df['status'] = df['label'].map({'good': 0, 'bad': 1})
        else:
            print("Error: Could not find Label column")
            return
            
    except FileNotFoundError:
        print(f"Error: Dataset not found at {DATA_PATH}")
        return
    
    print("Extracting lexical features for training...")
    feature_dicts = []
    
    # Process all URLs (or use .head(10000) for faster training)
    for idx, url in enumerate(df['URL']):
        if idx % 10000 == 0:
            print(f"Processed {idx}/{len(df)} URLs...")
        try:
            feature_dicts.append(extract_lexical_features(str(url)))
        except Exception as e:
            print(f"Error processing URL {url}: {e}")
            # Add default features for failed URLs
            feature_dicts.append({
                'url_length': 0, 'domain_length': 0, 'special_char_count': 0,
                'digit_count': 0, 'letter_count': 0, 'entropy': 0,
                'is_ip': 0, 'is_shortener': 0, 'suspicious_tld': 0,
                'homograph_risk': 0, 'dot_count': 0, 'has_at_symbol': 0
            })
    
    features_df = pd.DataFrame(feature_dicts)
    y = df['status'].values
    
    print(f"Feature set shape: {features_df.shape}")
    print(f"Label distribution: {pd.Series(y).value_counts().to_dict()}")
    
    print("Scaling features...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(features_df)
    
    # Split
    X_train, X_val, y_train, y_val = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # 1. Train XGBoost
    print("\n" + "="*50)
    print("Training XGBoost...")
    print("="*50)
    xgb_model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        use_label_encoder=False,
        eval_metric='logloss'
    )
    xgb_model.fit(X_train, y_train)
    
    val_acc_xgb = xgb_model.score(X_val, y_val)
    print(f"✅ XGBoost Validation Accuracy: {val_acc_xgb:.4f}")
    
    # 2. Train MLP
    print("\n" + "="*50)
    print("Training MLP (Neural Network)...")
    print("="*50)
    mlp_model = build_mlp_model(X_train.shape[1])
    early_stop = EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True)
    
    mlp_model.fit(
        X_train, y_train,
        epochs=30,
        batch_size=64,
        validation_data=(X_val, y_val),
        callbacks=[early_stop],
        verbose=1
    )
    
    # Save Artifacts
    print("\n" + "="*50)
    print("Saving models...")
    print("="*50)
    xgb_model.save_model(XGB_MODEL_PATH)
    mlp_model.save(MLP_MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    
    print(f"✅ Models saved:")
    print(f"   - {XGB_MODEL_PATH}")
    print(f"   - {MLP_MODEL_PATH}")
    print(f"   - {SCALER_PATH}")
    print("\n🎉 Training complete! System ready for server.py")

if __name__ == '__main__':
    main()
