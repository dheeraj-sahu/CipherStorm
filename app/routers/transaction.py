# routers/transaction.py
from fastapi import APIRouter, Depends, HTTPException, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import desc
from uuid import uuid4
from datetime import datetime
from app.models.constant import IST
import json
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.schemas.transaction import TransactionInput, FraudPredictionResponse
from app.models.transaction import Transaction
from app.models.profile import Profile
from app.models.user import User
from app.database import get_db
from app.services.fraud_service import run_fraud_pipeline
from app.services.device_service import calculate_derived_columns
from app.routers.auth import get_current_user
from app.config import settings

router = APIRouter(prefix="/transaction", tags=["Transaction"])
templates = Jinja2Templates(directory="app/templates")

# Store OTP temporarily (in production, use Redis or database)
otp_store = {}

@router.get("/", response_class=HTMLResponse)
async def get_transaction_form(request: Request, current_user: dict = Depends(get_current_user)):
    """Render the transaction form page"""
    return templates.TemplateResponse("transaction_form.html", {"request": request, "user": current_user})

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
    now = datetime.now(IST)
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

    # Routing logic based on fraud detection results
    if new_txn.is_fraud:
        # Step-up authentication: Send OTP
        otp = random.randint(100000, 999999)
        otp_store[profile.upi_id] = otp  # Store OTP
        
        # Send OTP via email (assuming user's email is available in profile)
        msg = MIMEMultipart()
        msg['From'] = settings.EMAIL_FROM
        msg['To'] = profile.email
        msg['Subject'] = 'Your OTP Code'
        body = f"Your OTP code is {otp}. It is valid for 10 minutes."
        msg.attach(MIMEText(body, 'plain'))
        
        # Send email
        with smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT) as server:
            server.starttls()
            server.login(settings.EMAIL_FROM, settings.EMAIL_PASSWORD)
            server.send_message(msg)
        
        return {"detail": "Fraud detected. OTP sent to registered email."}
    
    return result

@router.post("/verify_otp")
def verify_otp(
    request: Request,
    otp: int = Form(...),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    profile = db.query(Profile).filter(Profile.user_id == current_user.user_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="User profile not found")
    
    # Verify OTP
    stored_otp = otp_store.get(profile.upi_id)
    if not stored_otp or stored_otp != otp:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")
    
    # OTP verified, remove from store
    del otp_store[profile.upi_id]

    return {"detail": "OTP verified successfully. Transaction approved."}

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

@router.post("/process", response_class=HTMLResponse)
async def process_transaction(
    request: Request,
    amount: float = Form(...),
    transaction_type: str = Form(...),
    payment_method: str = Form(...),
    recipient_upi_id: str = Form(...),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Process transaction and route based on fraud detection results"""
    try:
        profile = db.query(Profile).filter(Profile.user_id == current_user.user_id).first()
        user = db.query(User).filter(User.user_id == current_user.user_id).first()
        
        if not profile:
            raise HTTPException(status_code=404, detail="User profile not found")

        # Generate timestamp features
        now = datetime.now()
        is_night = now.hour < 6 or now.hour > 22

        # Calculate derived columns
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

        # Create transaction object for fraud detection (don't save yet)
        txn_id = str(uuid4())
        temp_txn = Transaction(
            transaction_id=txn_id,
            user_id=current_user.user_id,
            amount=amount,
            transaction_type=transaction_type,
            payment_instrument=payment_method,
            payer_vpa=profile.upi_id,
            beneficiary_vpa=recipient_upi_id,
            initiation_mode=derived_data["initiation_mode"],
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

        # Get count of past transactions for the user
        txn_count = db.query(Transaction).filter(Transaction.user_id == current_user.user_id).count()

        # Run fraud detection
        fraud_result = run_fraud_pipeline(
            temp_txn, 
            profile, 
            txn_count=txn_count, 
            last_transaction_location=last_transaction_location,
            db_session=db
        )

        # Prepare transaction data for templates
        transaction_data = {
            "transaction_id": txn_id,
            "amount": amount,
            "transaction_type": transaction_type,
            "payment_method": payment_method,
            "to_account": recipient_upi_id,
            "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
            "from_account": profile.upi_id
        }

        # Save transaction data in session if fraud is detected
        if fraud_result["final_prediction"] == 1:  # Fraud detected
            # Store transaction data in session for step-up auth
            transaction_json = json.dumps({
                **transaction_data,
                "temp_txn_data": {
                    "amount": amount,
                    "transaction_type": transaction_type,
                    "payment_method": payment_method,
                    "recipient_upi_id": recipient_upi_id,
                    "derived_data": derived_data,
                    "txn_count": txn_count,
                    "last_transaction_location": last_transaction_location
                }
            })
            
            # Don't save transaction yet, wait for verification
            return templates.TemplateResponse(
                "transaction_results.html",
                {
                    "request": request,
                    "user": current_user,
                    "transaction_data": transaction_data,
                    "fraud_report": fraud_result,
                    "requires_verification": True,
                    "transaction_json": transaction_json
                }
            )
        else:  # No fraud detected
            # Save the transaction
            db.add(temp_txn)
            temp_txn.is_fraud = False
            db.commit()
            db.refresh(temp_txn)
            
            return templates.TemplateResponse(
                "transaction_results.html",
                {
                    "request": request,
                    "user": current_user,
                    "transaction_data": transaction_data,
                    "fraud_report": fraud_result,
                    "requires_verification": False
                }
            )
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Transaction processing failed: {str(e)}")

@router.post("/auth/step-up-verify", response_class=HTMLResponse)
async def step_up_verify(
    request: Request,
    action: str = Form(...),
    email: str = Form(None),
    otp: str = Form(None),
    transaction_data: str = Form(None),
    smtp_server: str = Form(None),
    smtp_port: str = Form(None),
    smtp_email: str = Form(None),
    smtp_password: str = Form(None),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Handle step-up authentication for suspicious transactions"""
    try:
        # Prepare SMTP settings from form data
        smtp_settings = {
            'smtp_server': smtp_server,
            'smtp_port': smtp_port,
            'smtp_email': smtp_email,
            'smtp_password': smtp_password
        } if all([smtp_server, smtp_port, smtp_email, smtp_password]) else None

        if action == "send_otp":
            # Generate and send OTP
            otp_code = str(random.randint(100000, 999999))
            otp_store[email] = otp_code
            
            # Send OTP email using provided SMTP settings
            success = send_otp_email(email, otp_code, smtp_settings)
            
            if success:
                return templates.TemplateResponse(
                    "step_up.html",
                    {
                        "request": request,
                        "user": current_user,
                        "otp_sent": True,
                        "user_email": email,
                        "transaction_data": transaction_data,
                        "success": "OTP sent successfully to your email!"
                    }
                )
            else:
                return templates.TemplateResponse(
                    "step_up.html",
                    {
                        "request": request,
                        "user": current_user,
                        "user_email": email,
                        "transaction_data": transaction_data,
                        "error": "Failed to send OTP. Please try again."
                    }
                )
                
        elif action == "verify_otp":
            # Verify OTP and process transaction
            if email in otp_store and otp_store[email] == otp:
                # OTP verified successfully, save the suspicious transaction
                del otp_store[email]  # Remove used OTP
                
                try:
                    # Parse the transaction data from the form - handle both string and dict formats
                    if isinstance(transaction_data, str):
                        try:
                            txn_data = json.loads(transaction_data)
                        except json.JSONDecodeError:
                            # Try to evaluate as a string representation of a dict
                            try:
                                txn_data = eval(transaction_data)
                            except:
                                txn_data = {"data": transaction_data}
                    else:
                        txn_data = transaction_data
                    
                    # Handle case where transaction data might be nested
                    if isinstance(txn_data, str):
                        try:
                            txn_data = json.loads(txn_data)
                        except json.JSONDecodeError:
                            try:
                                txn_data = eval(txn_data)
                            except:
                                txn_data = {"data": txn_data}
                    
                    # Extract temp_data, handling both possible structures
                    if "temp_txn_data" in txn_data:
                        temp_data = txn_data["temp_txn_data"]
                    else:
                        temp_data = txn_data

                    # Get profile for the current user to use as fallback
                    profile = db.query(Profile).filter(Profile.user_id == current_user.user_id).first()
                    # Get transaction ID or generate new one
                    txn_id = txn_data.get("transaction_id") or str(uuid4())
                    
                    # Create transaction with careful data handling
                    transaction = Transaction(
                        user_id=current_user.user_id,
                        transaction_id=txn_id,
                        amount=float(temp_data.get("amount", 0)),
                        transaction_type=temp_data.get("transaction_type", "unknown"),
                        payment_instrument=temp_data.get("payment_method", "unknown"),
                        payer_vpa=profile.upi_id if profile else "",
                        beneficiary_vpa=temp_data.get("recipient_upi_id", ""),
                        is_fraud=True,  # Mark as suspicious but verified
                        created_at=datetime.now(IST),
                        # Add derived data if available
                        device_id=temp_data.get("derived_data", {}).get("device_id", "unknown"),
                        ip_address=temp_data.get("derived_data", {}).get("ip_address", "unknown"),
                        latitude=temp_data.get("derived_data", {}).get("latitude", 0.0),
                        longitude=temp_data.get("derived_data", {}).get("longitude", 0.0),
                        country=temp_data.get("derived_data", {}).get("country", "unknown"),
                        city=temp_data.get("derived_data", {}).get("city", "unknown")
                    )
                
                    db.add(transaction)
                    db.commit()
                    
                    # Redirect to identity verified success page
                    return templates.TemplateResponse(
                        "identity_verified.html",
                        {
                            "request": request,
                            "user": current_user
                        }
                    )
                except Exception as e:
                    print(f"Error processing transaction data: {str(e)}")
                    print(f"Transaction data: {transaction_data}")
                    return templates.TemplateResponse(
                        "step_up.html",
                        {
                            "request": request,
                            "user": current_user,
                            "otp_sent": True,
                            "user_email": email,
                            "transaction_data": transaction_data,
                            "error": f"Failed to process transaction: {str(e)}"
                        }
                    )
                
                db.add(transaction)
                db.commit()
                
                # Redirect to identity verified success page
                return templates.TemplateResponse(
                    "identity_verified.html",
                    {
                        "request": request,
                        "user": current_user
                    }
                )
            else:
                return templates.TemplateResponse(
                    "step_up.html",
                    {
                        "request": request,
                        "user": current_user,
                        "otp_sent": True,
                        "user_email": email,
                        "transaction_data": transaction_data,
                        "error": "Invalid OTP. Please try again."
                    }
                )
                
        elif action == "resend_otp":
            # Resend OTP
            otp_code = str(random.randint(100000, 999999))
            otp_store[email] = otp_code
            
            # Send OTP email using provided SMTP settings
            success = send_otp_email(email, otp_code, smtp_settings)
            
            return templates.TemplateResponse(
                "step_up.html",
                {
                    "request": request,
                    "user": current_user,
                    "otp_sent": True,
                    "user_email": email,
                    "transaction_data": transaction_data,
                    "success": "OTP resent successfully!" if success else "Failed to resend OTP."
                }
            )
            
    except Exception as e:            # Log the error details for debugging
            print(f"Error in step_up_verify: {str(e)}")
            print(f"Transaction data type: {type(transaction_data)}")
            print(f"Transaction data content: {transaction_data}")
            
            return templates.TemplateResponse(
                "step_up.html",
                {
                    "request": request,
                    "user": current_user,
                    "user_email": email,
                    "transaction_data": transaction_data,
                    "error": f"An error occurred: {str(e)}"
                }
            )

@router.post("/auth/step-up")
async def step_up(
    request: Request,
    transaction_data: str = Form(...),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Handle step-up verification initiation"""
    try:
        # Keep transaction_data as string, don't parse it here
        user = db.query(User).filter(User.user_id == current_user.user_id).first()
        
        return templates.TemplateResponse(
            "step_up.html", 
            {
                "request": request,
                "user": current_user,
                "transaction_data": transaction_data,  # Pass as is
                "user_email": user.email if user else None
            }
        )
    except Exception as e:
        print(f"Error in step_up: {str(e)}")
        print(f"Transaction data type: {type(transaction_data)}")
        print(f"Transaction data content: {transaction_data}")
        raise HTTPException(status_code=500, detail=f"Step-up verification failed: {str(e)}")

@router.get("/transactions", response_class=HTMLResponse)
async def view_transactions(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/auth/login")
    
    # Get all transactions for the current user, ordered by most recent first
    transactions = (db.query(Transaction)
                   .filter(Transaction.user_id == user.user_id)
                   .order_by(desc(Transaction.created_at))
                   .all())
    
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "transactions": transactions
        }
    )

def send_otp_email(to_email: str, otp_code: str, smtp_settings: dict = None) -> bool:
    """Send OTP email using provided SMTP settings or default settings"""
    try:
        msg = MIMEMultipart()
        msg['From'] = smtp_settings.get('smtp_email') if smtp_settings else settings.SMTP_EMAIL
        msg['To'] = to_email
        msg['Subject'] = 'Your CipherStorm Transaction OTP'
        
        body = f"""
        Your OTP for CipherStorm transaction verification is: {otp_code}
        
        This OTP will expire in 10 minutes.
        If you did not request this OTP, please ignore this email.
        
        Best regards,
        CipherStorm Security Team
        """
        msg.attach(MIMEText(body, 'plain'))
        
        # Use provided SMTP settings or fall back to default settings
        smtp_server = smtp_settings.get('smtp_server', 'smtp.gmail.com')
        smtp_port = int(smtp_settings.get('smtp_port', 587))
        smtp_email = smtp_settings.get('smtp_email', settings.SMTP_EMAIL)
        smtp_password = smtp_settings.get('smtp_password', settings.SMTP_PASSWORD)
        
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_email, smtp_password)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Failed to send email: {str(e)}")
        return False