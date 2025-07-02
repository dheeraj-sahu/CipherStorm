from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

app = FastAPI()
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

def get_current_user(request: Request):
    return request.cookies.get("user")

@app.get("/", response_class=HTMLResponse)
async def landing(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "user": get_current_user(request)})

@app.get("/features", response_class=HTMLResponse)
async def features(request: Request):
    return templates.TemplateResponse("features.html", {"request": request, "user": get_current_user(request)})

@app.get("/contact", response_class=HTMLResponse)
async def contact(request: Request):
    return templates.TemplateResponse("contact.html", {"request": request, "user": get_current_user(request)})

@app.get("/login")
def login():
    return {"message": "Login endpoint"}

@app.get("/signup")
def signup():
    return {"message": "Signup endpoint"}

@app.get("/dashboard")
def dashboard():
    return {"message": "Dashboard endpoint"}

@app.get("/logout")
def logout():
    resp = HTMLResponse(content="<script>location.replace('/')</script>")
    resp.delete_cookie("user")
    return resp