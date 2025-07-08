from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from app.utils import get_current_user as get_current_user_util

router = APIRouter(prefix="/services", tags=["Services"])
templates = Jinja2Templates(directory="app/templates")

@router.get("/", response_class=HTMLResponse)
async def services_page(request: Request):
    """Main services page displaying all available security services"""
    user = get_current_user_util(request)
    return templates.TemplateResponse(
        "services.html", 
        {
            "request": request,
            "user": user
        }
    )

@router.get('/make-transaction',response_class=HTMLResponse)
async def make_transaction_page(request: Request):
    """Page to make a transaction"""
    user = get_current_user_util(request)
    return templates.TemplateResponse(
        "transaction_form.html", 
        {
            "request": request,
            "user": user
        }
    )