from fastapi import APIRouter, HTTPException, status, Depends, Form, BackgroundTasks, Request
from schemas import User, UserCreate, ClientResponse
from auth import DatabaseManager, PasswordManager, TokenFactory, UserManager
from database import create_connection
import logging
from mysql.connector import Error
import pyotp
from fastapi.security import OAuth2PasswordRequestForm
import secrets
from datetime import timedelta, timezone, datetime
from typing import Union
from aiosmtplib import send
from email.message import EmailMessage


router = APIRouter()
fake_db = {}

# The response_model parameter is used in FastAPI to specify the format of the data that the endpoint should return to the client.
@router.post('/register', response_model=User)
def register(user:UserCreate):

    try:
        # lets check if the user already exsists within table
        query_user = "SELECT * FROM users where username = %s"
        params_user = (user.username,)

        with DatabaseManager() as db:
            result = db.execute_read(query_user, params_user)

        if result:
            raise HTTPException(status_code=200, detail="Username already registered!")

        hashed_password = PasswordManager.hash_password(user.password)

        if user.twoFA_enabled:

            try:
                connection = create_connection()
                cursor = connection.cursor()
                # start a transaction batch
                connection.start_transaction()

                # query params for pushing into users
                query_Users = "INSERT INTO users (username, email, password, role_id, enabled) VALUES (%s, %s, %s, %s, %s)"
                params_Users = (user.username, user.email, hashed_password, user.role_id, True)

                cursor.execute(query_Users, params_Users)

                # get a secretotp for the user(which is used later to generate unique otp everytime later)
                add_otpSecret = pyotp.random_base32()

                # query params for pushing into otp_table
                query_Otp ='''INSERT INTO otp_table (username, otp_secret) VALUES (%s, %s)
                    ON DUPLICATE KEY
                    UPDATE otp_secret = IF(otp_secret IS NULL, VALUES(otp_secret), otp_Secret)
                    '''
                
                params_Otp = (user.username, add_otpSecret)
                cursor.execute(query_Otp, params_Otp)

                connection.commit()
                cursor.close()
                
            except Error as err:
                logging.error(str(err))
                connection.rollback()
                logging.error("Transaction rolled back")
                raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,detail='Error while writing into database')
            
            
        query = "INSERT INTO users (username, email, password, role_id) VALUES (%s, %s, %s, %s)"
        params = (user.username, user.email, hashed_password, user.role_id)

        with DatabaseManager() as db:
            db.execute_manipulation(query, params)

        return user
    
    except Exception as err:
        if not isinstance(err, HTTPException):
            logging.error(str(err))
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')
        else:
            raise

    finally:
        if connection:
            connection.close()


@router.post('/request-password-reset/')
def request_password_reset(user:User, background_task:BackgroundTasks):
    token = secrets.token_urlsafe(32)
    email = 'testuser@example.com'
    expiration = datetime.now(timezone.utc) + timedelta(minutes=10)
    
    fake_db[email] = {"reset_token": token, "expires_at": expiration}


@router.post("/login")
def login(form_data:OAuth2PasswordRequestForm = Depends()):

    try:
        user = form_data.username
        plain_pwd = form_data.password

        param_user = (user,)
        with DatabaseManager() as db:
            query_user = "SELECT * FROM users WHERE username = %s"
            user_db = db.execute_read(query_user, param_user)

        if user_db:
            resp_pwd = user_db.get('password')
            resp_role = user_db.get('role_id')

            if resp_pwd and PasswordManager.verify_password(plain_pwd, resp_pwd):

                if user_db.get('enabled') == 1 or user_db.get('enabled') == True:

                    '''For user who have enabled twofa(password and otp)'''

                    with DatabaseManager() as db:
                        query_otp = "SELECT * FROM otp_table WHERE username = %s"
                        otp_details = db.execute_read(query_otp, param_user)

                    if otp_details.get('otp_secret'):
                        otp = pyotp.TOTP(otp_details.get('otp_secret'))
                        otp_gen = otp.now()
                        
                        '''Send this otp  to the user chosen medium of communication(otp sent as email or sms or both)
                        but now, will include otp within the login reponse for testing purpose
                        will change it later when notification feature is added.'''

                        return {'stat': 'Ok', 'otp': otp_gen,"Result": "OTP sent to the registered mobile number/email"}

                    else:

                        '''Reset the twofa as disabled and ask to relogin as the otp_secrt data for the user not found in database.
                        Can be set /update_twofa endpoint once the user login with password'''

                        with DatabaseManager() as db:
                            false_query = "UPDATE users SET enabled = %s WHERE username = %s AND enabled = %s"
                            false_params = (False, user, True)
                            db.execute_manipulation(false_query, false_params)
                        
                        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"OTP data not found for user: {user}, Please try login again!")

                '''For users with only password authentication'''

                data ={"sub":user, 'role': resp_role}

                access_token = TokenFactory.create_access_token(data=data)

                return {"access_token": access_token, "token_type":"bearer"}

            else:
                '''When wrong password entered'''
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid Password")
                
        else:
            '''When username entered not valid'''
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="User not found")
        
    except Exception as err:
        if not isinstance(err, HTTPException):
            logging.error(str(err))
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')
        else:
            raise

@router.post('/verify_otp/')
def verify_otp(username: str = Form(...), otp:str = Form(...)):

    try:

        with DatabaseManager() as db:
            otp_query = "SELECT * FROM otp_table WHERE username = %s"
            otp_params = (username,)

            otp_details = db.execute_read(otp_query, otp_params)

        if pyotp.TOTP(otp_details.get('otp_secret')).verify(otp):

            user_query = "SELECT * FROM users WHERE username = %s"

            with DatabaseManager() as db:
                user = db.execute_read(user_query, otp_params)
            
            data = {'sub': otp_details.get('username'), 'role': user.get('role_id')}

            access_token = TokenFactory.create_access_token(data)

            return {"access_token": access_token, "token_type": "bearer"}
        
        logging.error(f"username:{username}, Error: Invalid OTP")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP")
    
    except Exception as err:
        if not isinstance(err, HTTPException):
            logging.error(f"username:{username}, Error:{str(err)}")
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')
        else:
            raise


@router.post('/logout/', response_model=Union[ClientResponse])
async def logout_me(request:Request, 
                      username:str = Form(...),
                      current_user: None = Depends(TokenFactory.validate_token)):    
    try:
    
        user = await UserManager.logout_user(username, request)
        return user

    except Exception as err:
        if not isinstance(err, HTTPException):
            logging.error(str(err))
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')
        else:
            raise


@router.put('/update-twofa')
async def update_twofa(user : str = Depends(TokenFactory.validate_token), 
                       twoFA_enabled:bool= Form(False)):
    try:
        username = user[0]   

        if not twoFA_enabled:
            '''when twoFA_enabled param is False'''

            # here we just need to update the enabled column of users table as False
            with DatabaseManager() as db:
                false_query = "UPDATE users SET enabled = %s WHERE username = %s AND enabled = %s"
                false_params = (False, username, True)
                
                set_false = db.execute_manipulation(false_query, false_params)
            
            if set_false == 1:
                return {"stat": "Ok", "Result": f"twoFA disabled successfully for {username} "}
            else:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Could not update resource, twoFA already disabled")
            
        else:
            '''when twoFA_enabled param is True'''
            # here we have to do two things:
            # 1. check if the otp_secret in otp_table for the username is not None, 
            # if None then create a otpsecret and update, if not None then as is
            with DatabaseManager() as db:

                otp_scrt_query = "UPDATE otp_table SET otp_secret = %s WHERE username = %s AND otp_secret IS NULL"
                add_otpSecret = pyotp.random_base32()
                otp_scrt_param = (add_otpSecret, username)
                db.execute_manipulation(otp_scrt_query, otp_scrt_param)

            # 2. update the enabled column, checking if its already True, if not then update
            with DatabaseManager() as db:
                true_query = "UPDATE users SET enabled = %s WHERE username = %s AND enabled = %s"
                true_params = (True, username, False)
                set_true = db.execute_manipulation(true_query, true_params)

            if set_true == 1:
                return {"stat": "Ok", "Result": f"twoFA enabled successfully for {username} "}
            else:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Could not update resource, twoFA already enabled")

    except Exception as err:
        if not isinstance(err, HTTPException):
            logging.error(str(err))
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')    
        else:
            raise