# services/fraud_service.py
import pickle
import numpy as np
import math
import os
from datetime import datetime, timedelta
from collections import defaultdict
from sqlalchemy import func
import logging
import jwt
import time
import requests

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load Static Models (global) with error handling
try:
    with open("app/ml_models/global_model.pkl", "rb") as f:
        global_model = pickle.load(f)
    logger.info("Global model loaded successfully")
except FileNotFoundError:
    logger.error("Global model file not found")
    global_model = None

try:
    with open("app/ml_models/global_label_encoders.pkl", "rb") as f:
        global_label_encoders = pickle.load(f)
    logger.info("Global label encoders loaded successfully")
except FileNotFoundError:
    logger.error("Global label encoders file not found")
    global_label_encoders = {}

try:
    with open("app/ml_models/global_freq_encoders.pkl", "rb") as f:
        global_freq_encoders = pickle.load(f)
    logger.info("Global frequency encoders loaded successfully")
except FileNotFoundError:
    logger.error("Global frequency encoders file not found")
    global_freq_encoders = {}

# Load Layer 3 Local Model Encoders
try:
    with open("app/ml_models/label_encoders.pkl", "rb") as f:
        local_label_encoders = pickle.load(f)
    logger.info("Local label encoders loaded successfully")
except FileNotFoundError:
    logger.error("Local label encoders file not found")
    local_label_encoders = {}

try:
    with open("app/ml_models/freq_encoders.pkl", "rb") as f:
        local_freq_encoders = pickle.load(f)
    logger.info("Local frequency encoders loaded successfully")
except FileNotFoundError:
    logger.error("Local frequency encoders file not found")
    local_freq_encoders = {}

def haversine(lat1, lon1, lat2, lon2):
    """Calculate the great circle distance between two points on earth"""
    R = 6371  # Earth's radius in kilometers
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (
        math.sin(dlat / 2) ** 2 +
        math.cos(math.radians(lat1)) *
        math.cos(math.radians(lat2)) *
        math.sin(dlon / 2) ** 2
    )
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

def calculate_amount_bin(amount):
    """Calculate amount bin for global model using the specified ranges"""
    amount = float(amount)
    if amount <= 2000:
        return 0  # Low
    elif amount <= 16000:
        return 1  # Medium
    else:
        return 2  # High

def is_amount_outlier(amount, amount_mean, amount_std):
    """Determine if amount is an outlier using Z-score > 3"""
    amount = float(amount)
    amount_mean = float(amount_mean)
    amount_std = float(amount_std)
    
    if amount_std == 0:  # Avoid division by zero
        return 0
    z_score = abs((amount - amount_mean) / amount_std)
    return 1 if z_score > 3 else 0

def calculate_amount_stats_from_db(db, user_id=None):
    """Calculate amount statistics from database for outlier detection"""
    from app.models.transaction import Transaction
    
    if user_id:
        # Calculate stats for specific user
        amounts = db.query(Transaction.amount).filter(Transaction.user_id == user_id).all()
    else:
        # Calculate global stats
        amounts = db.query(Transaction.amount).all()
    
    if not amounts:
        return 5000.0, 2500.0  # Default values if no transactions
    
    amounts = [float(a[0]) for a in amounts if a[0] is not None]
    if not amounts:
        return 5000.0, 2500.0
        
    amount_mean = np.mean(amounts)
    amount_std = np.std(amounts, ddof=0)
    
    return amount_mean, amount_std

def handle_new_category_label_encoder(encoder, value):
    """Handle new categories for label encoders by adding them with new IDs"""
    str_value = str(value) if value is not None else "Unknown"
    
    if not hasattr(encoder, 'classes_'):
        # Initialize if classes_ doesn't exist
        encoder.classes_ = np.array([str_value])
        return 0
    
    if str_value in encoder.classes_:
        return encoder.transform([str_value])[0]
    else:
        # Add new category with next available ID
        new_id = len(encoder.classes_)
        encoder.classes_ = np.append(encoder.classes_, str_value)
        return new_id

def handle_new_category_freq_encoder(encoder_dict, value):
    """Handle new categories for frequency encoders by adding them with frequency 1"""
    str_value = str(value) if value is not None else "Unknown"
    
    if str_value not in encoder_dict:
        encoder_dict[str_value] = 1  # Start with frequency 1 for new categories
    
    return encoder_dict[str_value]

def encode_categorical_features(data_dict, label_encoders, freq_encoders):
    """Encode categorical features using label encoders and frequency encoders with fallback for new categories"""
    encoded_dict = {}
    
    for key, value in data_dict.items():
        if key in label_encoders:
            encoded_dict[key] = handle_new_category_label_encoder(label_encoders[key], value)
        elif key in freq_encoders:
            encoded_dict[key] = handle_new_category_freq_encoder(freq_encoders[key], value)
        else:
            # Keep numerical features as is
            encoded_dict[key] = value
    
    return encoded_dict

def prepare_global_features(transaction_obj, profile_obj, amount_mean, amount_std):
    """Prepare features for global model exactly as specified"""
    amount = float(transaction_obj.amount)
    
    global_features = {
        "AMOUNT": amount,
        "PAYER_VPA": profile_obj.upi_id if profile_obj.upi_id else "Unknown",
        "BENEFICIARY_VPA": transaction_obj.beneficiary_vpa if transaction_obj.beneficiary_vpa else "Unknown",
        "INITIATION_MODE": transaction_obj.initiation_mode if transaction_obj.initiation_mode else "00",
        "TRANSACTION_TYPE": transaction_obj.transaction_type if transaction_obj.transaction_type else "P2P",
        "IS_FRAUD": 0,  # Placeholder, not used for prediction
        "AMOUNT_BIN": calculate_amount_bin(amount),
        "IS_AMOUNT_OUTLIER": is_amount_outlier(amount, amount_mean, amount_std),
        "DAY_OF_WEEK": transaction_obj.day_of_week if transaction_obj.day_of_week is not None else 0,
        "HOUR": transaction_obj.hour if transaction_obj.hour is not None else 0,
        "MINUTE": transaction_obj.minute if transaction_obj.minute is not None else 0,
        "IS_NIGHT": int(transaction_obj.is_night) if transaction_obj.is_night is not None else 0
    }
    
    return global_features

def encode_local_features(transaction_obj):
    """Encode features for Layer 3 using local model encoders with fallback for new categories"""
    encoded_features = {}
    
    # Label encode categorical features
    categorical_features = {
        'DEVICE_ID': transaction_obj.device_id if transaction_obj.device_id else "Unknown",
        'TRANSACTION_TYPE': transaction_obj.transaction_type if transaction_obj.transaction_type else "P2P",
        'PAYMENT_INSTRUMENT': transaction_obj.payment_instrument if transaction_obj.payment_instrument else "UPI",
        'COUNTRY': transaction_obj.country if transaction_obj.country else "Unknown",
        'CITY': transaction_obj.city if transaction_obj.city else "Unknown"
    }
    
    for feature, value in categorical_features.items():
        if feature in local_label_encoders:
            encoded_features[feature] = handle_new_category_label_encoder(local_label_encoders[feature], value)
        else:
            encoded_features[feature] = -1
    
    # Frequency encode features
    freq_features = {
        'BENEFICIARY_VPA': transaction_obj.beneficiary_vpa if transaction_obj.beneficiary_vpa else "Unknown",
        'IP_ADDRESS': transaction_obj.ip_address if transaction_obj.ip_address else "Unknown"
    }
    
    for feature, value in freq_features.items():
        if feature in local_freq_encoders:
            encoded_features[feature] = handle_new_category_freq_encoder(local_freq_encoders[feature], value)
        else:
            encoded_features[feature] = 0
    
    return encoded_features

def verify_upi_id(upi_id):
    """Verify UPI ID using Paysprint API"""
    try:
        # Use raw JWT key (do NOT base64-decode it)
        jwt_secret = "UTA5U1VEQXdNREF4VFZSSmVrNUVWVEpPZWxVd1RuYzlQUT09"
        
        timestamp = int(time.time())
        partner_id = "CORP00001"
        reqid = f"req{timestamp}"  # Must be unique per request
        
        # JWT Payload
        payload = {
            "timestamp": timestamp,
            "partnerId": partner_id,
            "reqid": reqid
        }
        
        # Generate JWT Token
        token = jwt.encode(payload, jwt_secret, algorithm='HS256')
        
        # API Request
        url = "https://uat.paysprint.in/sprintverify-uat/api/v1/verification/upi_verify"
        
        api_payload = {
            "refid": f"txn{timestamp}",
            "id_number": upi_id
        }
        
        headers = {
            "accept": "application/json",
            "Token": token,
            "authorisedkey": "TVRJek5EVTJOelUwTnpKRFQxSlFNREF3TURFPQ==",
            "content-type": "application/json"
        }
        
        response = requests.post(url, json=api_payload, headers=headers)
        
        if response.status_code == 200:
            result = response.json()
            return result.get('data', {}).get('account_exists', False)
        else:
            logger.error(f"UPI verification failed with status code: {response.status_code}")
            return True  # Assume valid if API fails
            
    except Exception as e:
        logger.error(f"Error verifying UPI ID: {str(e)}")
        return True  # Assume valid if verification fails

def layer2_heuristics_check(transaction_obj, profile_obj):
    """Layer 2: Real-time heuristics check"""
    rules_triggered = []
    
    # 1. Check if transaction amount > 0.95 * transaction_limit
    if profile_obj.transaction_limit and float(transaction_obj.amount) > (0.95 * float(profile_obj.transaction_limit)):
        rules_triggered.append("Amount exceeds 95% of transaction limit")
    
    # 2. Check if current transaction country is different than profile country
    if (profile_obj.country and transaction_obj.country and 
        profile_obj.country.strip().lower() != transaction_obj.country.strip().lower()):
        rules_triggered.append("Transaction country differs from profile country")
    
    # 3. Check if UPI ID exists
    if transaction_obj.beneficiary_vpa:
        upi_exists = verify_upi_id(transaction_obj.beneficiary_vpa)
        if not upi_exists:
            rules_triggered.append("Invalid UPI ID")
    
    # Debug logging
    logger.info(f"Layer 2 Debug - Amount: {transaction_obj.amount}, Limit: {profile_obj.transaction_limit}")
    logger.info(f"Layer 2 Debug - Profile Country: {profile_obj.country}, Transaction Country: {transaction_obj.country}")
    logger.info(f"Layer 2 Debug - UPI ID: {transaction_obj.beneficiary_vpa}")
    logger.info(f"Layer 2 Rules Triggered: {rules_triggered}")
    
    return {
        'rules_triggered': rules_triggered,
        'is_suspicious': len(rules_triggered) > 0
    }

def get_user_transaction_stats(db_session, user_id):
    """Get user transaction statistics for rule-based detection (Layer 3)"""
    from app.models.transaction import Transaction
    
    # Get all past transactions for the user
    user_transactions = db_session.query(Transaction).filter(
        Transaction.user_id == user_id
    ).all()
    
    if not user_transactions:
        return {
            'amount_98_percentile': 0, 'amount_85_percentile': 0,
            'amount_70_percentile': 0, 'amount_80_percentile': 0,
            'amount_90_percentile': 0, 'distance_85_percentile': 0,
            'qr_threshold': 0, 'device_id_counts': {}, 'vpa_counts': {}, 'ip_counts': {}
        }
    
    amounts = [float(txn.amount) for txn in user_transactions if txn.amount is not None]
    
    # Calculate distances - need to add this field to transaction model or calculate dynamically
    distances = []
    for i, txn in enumerate(user_transactions[1:], 1):
        prev_txn = user_transactions[i-1]
        if (txn.latitude and txn.longitude and 
            prev_txn.latitude and prev_txn.longitude):
            dist = haversine(prev_txn.latitude, prev_txn.longitude,
                           txn.latitude, txn.longitude)
            distances.append(dist)
    
    if not distances:
        distances = [0]
    
    # Encode and count frequencies for encoded values
    device_counts = defaultdict(int)
    vpa_counts = defaultdict(int)
    ip_counts = defaultdict(int)
    
    for txn in user_transactions:
        # Encode each transaction's features
        encoded_features = encode_local_features(txn)
        
        # Count encoded values
        if encoded_features.get('DEVICE_ID') is not None:
            device_counts[encoded_features['DEVICE_ID']] += 1
        if encoded_features.get('BENEFICIARY_VPA') is not None:
            vpa_counts[encoded_features['BENEFICIARY_VPA']] += 1
        if encoded_features.get('IP_ADDRESS') is not None:
            ip_counts[encoded_features['IP_ADDRESS']] += 1
    
    # Calculate QR/Card threshold (payment_instrument == 1 means Card after encoding)
    qr_transactions = []
    for txn in user_transactions:
        encoded_features = encode_local_features(txn)
        if encoded_features.get('PAYMENT_INSTRUMENT') == 1:  # Card transactions
            qr_transactions.append(float(txn.amount))
    
    qr_threshold = (np.percentile(qr_transactions, 90) if qr_transactions 
                   else np.percentile(amounts, 90) if amounts else 0)
    
    return {
        'amount_98_percentile': np.percentile(amounts, 98) if amounts else 0,
        'amount_85_percentile': np.percentile(amounts, 85) if amounts else 0,
        'amount_70_percentile': np.percentile(amounts, 70) if amounts else 0,
        'amount_80_percentile': np.percentile(amounts, 80) if amounts else 0,
        'amount_90_percentile': np.percentile(amounts, 90) if amounts else 0,
        'distance_85_percentile': np.percentile(distances, 85) if distances else 0,
        'qr_threshold': qr_threshold,
        'device_id_counts': dict(device_counts),
        'vpa_counts': dict(vpa_counts),
        'ip_counts': dict(ip_counts)
    }

def rule_based_layer3_predict(transaction_obj, user_stats, distance_from_last):
    """Enhanced rule-based anomaly detection (Layer 3) based on user's historical data"""
    amount = float(transaction_obj.amount)
    rules_triggered = []

    # Use features as-is, do not encode again
    features = transaction_obj if isinstance(transaction_obj, dict) else {k: v for k, v in transaction_obj.__dict__.items() if not k.startswith('_')}

    # RULE 1: Extreme High Amount Transactions
    if amount > user_stats['amount_98_percentile']:
        rules_triggered.append("Extreme High Amount")
    
    # RULE 2: Night Transactions with Moderate-High Amounts
    if features.get('is_night', 0) and amount > user_stats['amount_80_percentile']:
        rules_triggered.append("Night High Amount")
    
    # RULE 3: Large Geographic Distance + High Amount
    if (distance_from_last > user_stats['distance_85_percentile'] and 
        amount > user_stats['amount_70_percentile']):
        rules_triggered.append("Geographic Distance + Amount")
    
    # RULE 4b: QR Transactions with High Amounts
    if (features.get('PAYMENT_INSTRUMENT') == 0 and 
        amount > user_stats['qr_threshold']):
        rules_triggered.append("High Amount QR Transaction")
    
    # RULE 5: Multiple Rare Patterns Combined
    encoded_device_id = features.get('DEVICE_ID', -1)
    encoded_vpa = features.get('BENEFICIARY_VPA', 0)
    rare_device = user_stats['device_id_counts'].get(encoded_device_id, 0) <= 2
    rare_vpa = user_stats['vpa_counts'].get(encoded_vpa, 0) <= 2
    moderate_amount = amount > user_stats['amount_80_percentile']
    if rare_device and rare_vpa and moderate_amount:
        rules_triggered.append("Multiple Rare Patterns")

    # Apply rule weights as per your local model
    rule_weights = {
        "Extreme High Amount": 1.0,
        "Night High Amount": 0.7,
        "Geographic Distance + Amount": 0.8,
        "High Amount QR Transaction": 0.6,
        "Multiple Rare Patterns": 0.9
    }

    # Calculate weighted confidence
    total_weight = sum(rule_weights.get(rule, 0.5) for rule in rules_triggered)
    max_possible_weight = sum(rule_weights.values())
    confidence = total_weight / max_possible_weight if max_possible_weight > 0 else 0

    # Predict anomaly if any rules triggered
    is_anomaly = len(rules_triggered) > 0
    
    return {
        'is_anomaly': int(is_anomaly),
        'rules_triggered': rules_triggered,
        'confidence': confidence,
        'total_weight': total_weight,
        'encoded_features': features
    }

def run_fraud_pipeline(transaction_obj, profile_obj, txn_count: int, last_transaction_location=None, db_session=None):
    """Main fraud detection pipeline with Layer 1 (Global) + Layer 2 (Heuristics) + Layer 3 (Rule-based)"""
    
    # Calculate amount statistics for outlier detection
    if db_session:
        amount_mean, amount_std = calculate_amount_stats_from_db(db_session, transaction_obj.user_id)
        user_stats = get_user_transaction_stats(db_session, transaction_obj.user_id)
    else:
        amount_mean, amount_std = 5000.0, 2500.0
        user_stats = {
            'amount_98_percentile': 0, 'amount_85_percentile': 0,
            'amount_70_percentile': 0, 'amount_80_percentile': 0,
            'amount_90_percentile': 0, 'distance_85_percentile': 0,
            'qr_threshold': 0, 'device_id_counts': {}, 'vpa_counts': {}, 'ip_counts': {}
        }
    
    # Calculate distance from last location
    distance_from_last = 0.0
    if (last_transaction_location and transaction_obj.latitude and transaction_obj.longitude):
        distance_from_last = haversine(
            transaction_obj.latitude, transaction_obj.longitude,
            last_transaction_location['latitude'], last_transaction_location['longitude']
        )

    # --- LAYER 1: Global Model Prediction ---
    global_score = 0.5  # Default score
    if global_model is not None:
        global_features = prepare_global_features(transaction_obj, profile_obj, amount_mean, amount_std)
        global_features_encoded = encode_categorical_features(
            global_features, global_label_encoders, global_freq_encoders)
        
        # Convert to array for prediction (maintaining order as specified)
        feature_order = ["AMOUNT", "PAYER_VPA", "BENEFICIARY_VPA", "INITIATION_MODE", 
                        "TRANSACTION_TYPE", "AMOUNT_BIN", "IS_AMOUNT_OUTLIER",
                        "DAY_OF_WEEK", "HOUR", "MINUTE", "IS_NIGHT"]
        
        X_global = np.array([[global_features_encoded.get(feature, 0) for feature in feature_order]])
        global_score = global_model.predict_proba(X_global)[0][1]

    # --- LAYER 2: Real-time Heuristics Check ---
    layer2_result = layer2_heuristics_check(transaction_obj, profile_obj)

    # --- LAYER 3: Rule-based Local Model Prediction ---
    
     # Only apply Layer 3 after 10 transactions
    if txn_count > 10:
        # First encode the transaction features for Layer 3
        encoded_features = encode_local_features(transaction_obj)
        
        # Create a transaction object with encoded features for Layer 3
        transaction_with_encoded = type('obj', (object,), {
            **transaction_obj.__dict__,
            **encoded_features
        })()
        
        layer3_result = rule_based_layer3_predict(transaction_with_encoded, user_stats, distance_from_last)
    else:
        # For first 10 transactions, return empty Layer 3 result
        layer3_result = {
            'is_anomaly': 0,
            'rules_triggered': [],
            'confidence': 0.0,
            'total_weight': 0.0,
            'encoded_features': {}
        }

    # --- Final Decision Fusion ---
    # Combine all layers
    if layer2_result['is_suspicious'] or layer3_result['is_anomaly']:
        final_score = (global_score * 0.3) + (0.4 if layer2_result['is_suspicious'] else 0) + (layer3_result['confidence'] * 0.3)
    else:
        final_score = global_score
    
    # Final prediction: fraud if any layer detects fraud
    final_prediction = int(final_score > 0.5 or layer2_result['is_suspicious'] or layer3_result['is_anomaly'])
    
    # Log scores from each layer
    logger.info("=== Fraud Detection Scores ===")
    logger.info(f"Global Model Score: {global_score:.3f}")
    logger.info(f"Layer 2 (Heuristics) Score: {0.4 if layer2_result['is_suspicious'] else 0:.3f}")
    logger.info(f"Layer 2 Rules Triggered: {layer2_result['rules_triggered']}")
    logger.info(f"Layer 3 (Local) Score: {layer3_result['confidence']:.3f}")
    logger.info(f"Layer 3 Rules Triggered: {layer3_result['rules_triggered']}")
    logger.info(f"Final Combined Score: {final_score:.3f}")
    logger.info(f"Final Prediction: {'Fraud' if final_prediction else 'Not Fraud'}")
    logger.info("=============================")

    return {
        "global_score": float(global_score),
        "layer2_score": 0.4 if layer2_result['is_suspicious'] else 0,
        "layer2_rules_triggered": layer2_result['rules_triggered'],
        "layer3_score": float(layer3_result['confidence']),
        "local_layer_pred": layer3_result['is_anomaly'],
        "rules_triggered": layer3_result['rules_triggered'],
        "final_score": float(final_score),
        "final_prediction": int(final_prediction)
}