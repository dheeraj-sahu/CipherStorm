from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from app.database import Base, engine
from app.routers import auth, user, profile, pages, edit, services, transaction, text, url,customer_care
# Import models to ensure tables are created
from app.models import user as user_model, profile as profile_model, transaction as transaction_model, customer_care as customer_care_model, vishing as vishing_model, text as text_model, url as url_model

app = FastAPI(title="Fraud Detection API")

# Mount static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

Base.metadata.create_all(bind=engine)

app.include_router(pages.router)
app.include_router(auth.router)
app.include_router(user.router)
app.include_router(profile.router)
app.include_router(edit.router)
app.include_router(services.router)
app.include_router(transaction.router)
app.include_router(text.router)
app.include_router(url.router)
app.include_router(customer_care.router)

from app.config import settings
import os
print(f"DATABASE_URL from config: {settings.DATABASE_URL}")
print(f"Current working directory: {os.getcwd()}")