from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from app.utils import get_current_user

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

@router.get("/", response_class=HTMLResponse)
async def landing(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "user": get_current_user(request)})

@router.get("/features", response_class=HTMLResponse)
async def features(request: Request):
    return templates.TemplateResponse("features.html", {"request": request, "user": get_current_user(request)})

@router.get("/contact", response_class=HTMLResponse)
async def contact(request: Request):
    return templates.TemplateResponse("contact.html", {"request": request, "user": get_current_user(request)})

@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "user": get_current_user(request), "dashboard": True})
