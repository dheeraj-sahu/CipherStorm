from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from app.database import Base, engine
from app.routers import auth, user, profile, pages, edit, services, transaction
# Import models to ensure tables are created
from app.models import user as user_model, profile as profile_model, transaction as transaction_model

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