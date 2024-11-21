from fastapi import APIRouter, HTTPException, BackgroundTasks, Form, Request, Depends
import logging
from datetime import datetime, timezone, timedelta
from auth_app.core import config
from auth_app.services import get_password_reset_service, PasswordResetService
from auth_app.utils import send_password_reset_email
from auth_app.schemas import User


router = APIRouter()

fake_db = {"suyogshashank@gmail.com": {"reset_token": "token", "expires_at": "expiration"},  }


@router.post('/request-password-reset/')
async def request_password_reset(user:User, background_task:BackgroundTasks, 
                           resetPwd_service:PasswordResetService = Depends(get_password_reset_service)):

    try:
        username = user.username
        email = user.email

        result = await resetPwd_service.request_password_reset(username=username, email=email)

        if isinstance(result,dict) and 'url_link' in result:

            link = result.get('url_link')

            background_task.add_task(send_password_reset_email, email, link)

        return {"stat":"Ok","Result": "Password reset email sent successfully"}


    except Exception as er:
        if not isinstance(er, HTTPException):
            logging.error(f"Error occured : {str(er)}")
            raise  HTTPException(500, detail="Internal Server Error")   
        else:
            raise 


@router.get('/reset-password/')
async def reset_password(request:Request, 
                   token: str,
                   resetPwd_service:PasswordResetService = Depends(get_password_reset_service)):
    # Retrieve and verify the token from the database
    
    try:
        result = await resetPwd_service.reset_password(token=token)

        if result == True:
            template_payload = {"request": request, "token": token}
            return config.templates.TemplateResponse("password_reset.html", template_payload)


    except Exception as er:
        if not isinstance(er, HTTPException):
            logging.error(f"Error occured : {str(er)}")
            raise  HTTPException(500, detail="Internal Server Error")   
        else:
            raise 


@router.post("/submit-new-password")
async def submit_new_password(token: str = Form(...), 
                        new_password:str = Form(...),
                        resetPwd_service:PasswordResetService = Depends(get_password_reset_service)):
    token = token
    new_password = new_password


    try:
        result = await resetPwd_service.submit_password(token=token,new_password=new_password)
        return result

    except Exception as er:
        if not isinstance(er, HTTPException):
            logging.error(f"Error occured : {str(er)}")
            raise  HTTPException(500, detail="Internal Server Error")   
        else:
            raise

