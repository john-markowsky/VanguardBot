from fastapi import FastAPI, Depends, HTTPException, status, Form, Request, Response
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import RedirectResponse
from passlib.context import CryptContext
from pydantic import BaseModel
from typing import List, Optional

from database import get_db, SessionLocal, engine
from models.db_models import Base, User, VanguardAccount, Account, Equity, VanguardLoginData, Vanguard2FAData
from browser_utility import initialize_vanguard_login, complete_vanguard_2fa
from schemas import user as user_schemas
from schemas.user import VanguardLoginRequest
from secure import encrypt_data, decrypt_data
from keys import ENCRYPTION_KEY, SESSION_SECRET_KEY

import crud
import logging
import subprocess
import json

logging.basicConfig(level=logging.INFO)
Base.metadata.create_all(bind=engine)

app = FastAPI()

app.mount("/static", StaticFiles(directory="./static"), name="static")
templates = Jinja2Templates(directory="templates")

app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET_KEY)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

from starlette.responses import RedirectResponse

# Global exception handler for HTTPException
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return templates.TemplateResponse("error.html", {"request": request, "detail": exc.detail}, status_code=exc.status_code)

# Global exception handler for any unhandled Exception
@app.exception_handler(Exception)
async def exception_handler(request: Request, exc: Exception):
    return templates.TemplateResponse("error.html", {"request": request, "detail": "An unexpected error occurred."}, status_code=500)

@app.get("/")
async def read_root(request: Request):
    user_id = request.session.get("user_id")
    if user_id:
        return RedirectResponse(url="/dashboard")
    else:
        return RedirectResponse(url="/login")

@app.get("/about")
async def about_page(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    user = None
    if user_id:
        user = crud.get_user_by_id(db, user_id=user_id)
    return templates.TemplateResponse("about.html", {"request": request, "user": user})

@app.get("/register")
def get_registration_form(request: Request, error_message: str = None):
    user_id = request.session.get("user_id")
    if user_id:
        response = RedirectResponse(url="/dashboard")
        return response
    return templates.TemplateResponse("register.html", {"request": request, "error_message": error_message})

@app.post("/register")
def register_user(request: Request, app_username: str = Form(...), app_hashed_password: str = Form(...), db: Session = Depends(get_db)):
    db_user = crud.get_user_by_username(db, username=app_username)
    if db_user:
        return get_registration_form(request, error_message="Username already registered")

    hashed_password = crud.get_password_hash(app_hashed_password)
    db_user = User(app_username=app_username, app_hashed_password=hashed_password)

    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    request.session["user_id"] = db_user.id

    return RedirectResponse(url="/profile", status_code=303)

@app.get("/profile")
def get_profile(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    user = crud.get_user_by_id(db, user_id=user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    vanguard_accounts = crud.get_vanguard_accounts_for_user(db, user_id=user_id)

    return templates.TemplateResponse("profile.html", {
        "request": request,
        "user": user,
        "vanguard_accounts": vanguard_accounts
    })

@app.get("/login")
async def login_form(request: Request):
    user_id = request.session.get("user_id")
    if user_id:
        response = RedirectResponse(url="/dashboard")
        return response
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login(request: Request, db: Session = Depends(get_db)):
    form_data = await request.form()
    username = form_data["username"]
    password = form_data["password"]

    user = crud.get_user_by_username(db, username)
    if not user or not pwd_context.verify(password, user.app_hashed_password):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error_message": "Incorrect username or password."
        })

    request.session["user_id"] = user.id

    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    return response

@app.get("/dashboard")
async def dashboard(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    
    user = crud.get_user_by_id(db, user_id=user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": user,
    })

@app.get("/logout")
async def logout(request: Request, response: Response):
    if "user_id" in request.session:
        del request.session["user_id"]
    response.headers["Location"] = "/login"
    response.status_code = status.HTTP_302_FOUND
    return response

@app.post("/vanguard-login/")
async def vanguard_login(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return {"status": "error", "message": "User not authenticated"}

    form_data = await request.form()
    username = form_data["username"]
    password = form_data["password"]

    logging.info(f"Received data: username={username}, password={password}, user_id={user_id}")
    result = await initialize_vanguard_login(user_id, username, password)
    
    if result.get("status") == "awaiting_2fa":
        # Save the Vanguard account details to the database
        crud.create_vanguard_account(db, username, password, user_id)
        return {"status": "awaiting_2fa"}
    elif result.get("status") == "error":
        return {"status": "error", "message": result.get("message")}
    else:
        return {"status": "unknown_error"}  

@app.post("/vanguard-2fa/")
async def vanguard_2fa(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return {"status": "error", "message": "User not authenticated"}

    form_data = await request.form()
    two_fa_code = form_data["two_fa_code"]

    logging.info(f"Received 2FA code: {two_fa_code}, for user_id: {user_id}")
    result = await complete_vanguard_2fa(user_id, two_fa_code)
    
    if result.get("status") == "success":
        # No need to save Vanguard account details here; already done in /vanguard-login/
        return {"status": "success"}
    else:
        return {"status": "error", "message": result.get("message", "Unknown error occurred.")}

##############################################
# CATCH ALL ENDPOINT DO NOT WRITE BELOW THIS #
##############################################
@app.get("/{full_path:path}")
async def catch_all(request: Request, full_path: str):
    return templates.TemplateResponse("error.html", {"request": request, "detail": "Page not found"}, status_code=404)
