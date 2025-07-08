# routers/transaction.py
from fastapi import APIRouter, Depends, HTTPException, Request, Form
from sqlalchemy.orm import Session
from uuid import uuid4
from datetime import datetime
from app.schemas.transaction import TransactionInput, FraudPredictionResponse
from app.models.transaction import Transaction
from app.models.profile import Profile
from app.database import get_db
from app.services.fraud_service import run_fraud_pipeline
from app.services.device_service import calculate_derived_columns
from app.routers.auth import get_current_user

router = APIRouter(prefix="/transaction", tags=["Transaction"])

@router.post("/", response_model=FraudPredictionResponse)
def create_and_predict_transaction(
    request: Request,
    amount: float = Form(...),
    transaction_type: str = Form(...),
    payment_method: str = Form(...),
    recipient_upi_id: str = Form(...),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    profile = db.query(Profile).filter(Profile.user_id == current_user.user_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="User profile not found")

    # Generate timestamp features
    now = datetime.now()
    is_night = now.hour < 6 or now.hour > 22

    # Calculate derived columns internally (device_id from cookie/header, location from IP)
    derived_data = calculate_derived_columns(request)

    # Get last transaction for distance calculation
    last_txn = db.query(Transaction).filter(
        Transaction.user_id == current_user.user_id
    ).order_by(Transaction.created_at.desc()).first()

    last_transaction_location = None
    if last_txn and last_txn.latitude and last_txn.longitude:
        last_transaction_location = {
            'latitude': float(last_txn.latitude),
            'longitude': float(last_txn.longitude)
        }

    # Save transaction
    txn_id = str(uuid4())
    new_txn = Transaction(
        transaction_id=txn_id,
        user_id=current_user.user_id,
        amount=amount,
        transaction_type=transaction_type,
        payment_instrument=payment_method,
        payer_vpa=profile.upi_id,
        beneficiary_vpa=recipient_upi_id,
        initiation_mode=derived_data["initiation_mode"],  # Always "Default"
        device_id=derived_data["device_id"],
        ip_address=derived_data["ip_address"],
        latitude=derived_data["latitude"],
        longitude=derived_data["longitude"],
        country=derived_data["country"],
        city=derived_data["city"],
        day_of_week=now.weekday(),
        hour=now.hour,
        minute=now.minute,
        is_night=is_night,
        created_at=now
    )
    db.add(new_txn)
    db.commit()
    db.refresh(new_txn)

    # Get count of past transactions for the user
    txn_count = db.query(Transaction).filter(Transaction.user_id == current_user.user_id).count()

    # Use model
    result = run_fraud_pipeline(
        new_txn, 
        profile, 
        txn_count=txn_count, 
        last_transaction_location=last_transaction_location,
        db_session=db
    )

    new_txn.is_fraud = bool(result["final_prediction"])
    db.commit()

    return result

@router.delete("/{txn_id}")
def delete_transaction(
    txn_id: str, 
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    txn = db.query(Transaction).get(txn_id)
    if not txn:
        raise HTTPException(status_code=404, detail="Transaction not found")
    db.delete(txn)
    db.commit()
    return {"msg": "Transaction deleted"}