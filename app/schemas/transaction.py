# schemas/transaction.py
from pydantic import BaseModel
from typing import Optional

class TransactionInput(BaseModel):
    amount: float
    transaction_type: str
    payment_method: str
    recipient_upi_id: str
    # Note: device_id will be extracted from request cookies/headers
    # initiation_mode, ip_address, latitude, longitude, country, city will be calculated internally

class FraudPredictionResponse(BaseModel):
    global_score: float
    local_layer_pred: int
    rules_triggered: list
    final_score: float
    final_prediction: int