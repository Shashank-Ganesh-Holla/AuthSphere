from fastapi import APIRouter, HTTPException, status, Depends, Form, BackgroundTasks, Request
from schemas import User, UserCreate, ClientResponse
from managers import UserManager
import logging
import pyotp
from fastapi.security import OAuth2PasswordRequestForm
import secrets
from datetime import timedelta, timezone, datetime
from typing import Union
from aiosmtplib import send
from services import AuthService
from utils import get_db_connection_batch_process, validate_token, send_password_reset_email
from core import websocket_manager
from services import get_auth_service
from fastapi.responses import HTMLResponse
from jinja2 import Template

router = APIRouter()


# Email client for development stage ✅

# reset password

# add another column in users table for token_store(admin only accessed, in case of account take over or ban, the active jwt token
# can be disregarded by admin)


# The response_model parameter is used in FastAPI to specify the format of the data that the endpoint should return to the client.
@router.post('/register', response_model= Union[ClientResponse, None])
async def register(user:UserCreate, 
                   auth_service:AuthService = Depends(get_auth_service),
                   db = Depends(get_db_connection_batch_process)): 
    

    try:

        '''user existance check before entering the auth service enhances the performance and reduces the latency'''

        user_exists = await UserManager.user_query(user.username)

        if user_exists: # if the user already in db
            logging.error("Username already registered!")
            raise HTTPException(status_code=400, detail="Username already registered!")
    
    except Exception as err:

        if isinstance(err, HTTPException) and err.detail == "User not found":
            
            '''we will create user when this condition satisfies'''

            try:
                result = await auth_service.register_user(username=user.username, email=user.email,
                                                          password=user.password,db=db, two_fa=user.twoFA_enabled)
                                                        
                return result
            
            except Exception as err:
                if not isinstance(err, HTTPException):
                    logging.error(f"Error occured : {str(err)}")

                    #Websocket broadcast
                    await websocket_manager.broadcast(f"{datetime.now()} : User: {user.username}, Result: {str(err)}")

                    raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")
                
                #Websocket broadcast
                await websocket_manager.broadcast(f"{datetime.now()} : User: {user.username}, Result: {err.detail}")

                raise 

        else:

            if not isinstance(err, HTTPException):
                logging.error(f"Error occured : {str(err)}")

                #Websocket broadcast
                await websocket_manager.broadcast(f"{datetime.now()} : User: {user.username}, Result: {str(err)}")

                raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")
            
            #Websocket broadcast
            await websocket_manager.broadcast(f"{datetime.now()} : User: {user.username}, Result: {err.detail}")

            raise 



@router.post("/login")
async def login(backgroudtasks : BackgroundTasks,form_data:OAuth2PasswordRequestForm = Depends(), 
                auth_service:AuthService = Depends(get_auth_service) ):

    try:

        '''user existance check doesnt seem benefitial here as we have to query users table for checking user and getting the stored password
        so the one time db query seems more logical'''

        result = await auth_service.login(backgroudtasks=backgroudtasks, username=form_data.username,
                        password=form_data.password)

        return result 

    except Exception as err:
        if not isinstance(err, HTTPException):
            logging.error(f"Error occured : {repr(err)}")

            #Websocket broadcast
            await websocket_manager.broadcast(f"{datetime.now()} : User: {form_data.username}, Result: {str(err)}")

            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")
        
        #Websocket broadcast
        await websocket_manager.broadcast(f"{datetime.now()} : User: {form_data.username}, Result: {err.detail}")

        raise 


@router.post('/verify_otp/')
async def verify_otp(username: str = Form(...), otp:str = Form(...), auth_service : AuthService = Depends(get_auth_service)):

    try:

        result = await auth_service.otp_verify(username=username, otp=otp)
        return result
    
    except Exception as err:
        if not isinstance(err, HTTPException):
            logging.error(f"username:{username}, Error:{str(err)}")

            #Websocket broadcast
            await websocket_manager.broadcast(f"{datetime.now()} : User: {username}, Result: {str(err)}")

            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')
        else:
            #Websocket broadcast
            await websocket_manager.broadcast(f"{datetime.now()} : User: {username}, Result: {err.detail}")

            raise


@router.post('/logout/', response_model=Union[ClientResponse])
async def logout_me(request:Request,
                      current_user = Depends(validate_token),
                      auth_service: AuthService = Depends(get_auth_service)):
    

    try:
        result = await auth_service.logout(request=request, username=current_user[0])
        return result
    
    except Exception as err:
        if not isinstance(err, HTTPException):
            logging.error(str(err))

            #Websocket broadcast
            await websocket_manager.broadcast(f"{datetime.now()} : User: {current_user}, Result: {str(err)}")

            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')
        else:
            #Websocket broadcast
            await websocket_manager.broadcast(f"{datetime.now()} : User: {current_user}, Result: {err.detail}")

            raise


@router.put('/update-twofa')
async def update_twofa(user : str = Depends(validate_token), 
                       twoFA_enabled:bool= Form(False),
                       auth_service: AuthService = Depends(get_auth_service)):
    try:
        username = user[0] 
        result = await auth_service.update_twoFa(username=username, twoFA_enabled=twoFA_enabled)
        return result
    

    except Exception as err:
        if not isinstance(err, HTTPException):
            logging.error(str(err))
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')    
        else:
            raise