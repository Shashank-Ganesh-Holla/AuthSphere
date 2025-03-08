from .db_connection import DatabaseManager
from fastapi import HTTPException, BackgroundTasks, Depends
import aiomysql
import logging
import pyotp
from .email_helper import send_otp_email



async def create_user_table_batch(username:str, email:str, hashed_password:str, 
                             database: aiomysql.Connection, 
                             role_id: int = 2, two_fa:bool = False):
    
    try:
   
        async with database.cursor() as cursor:
            query_Users = "INSERT INTO users (username, email, password, twofa_status, role_id) VALUES (%s, %s, %s, %s, %s)"
            params_Users = (username, email, hashed_password, two_fa, role_id)

            await cursor.execute(query_Users, params_Users)

            await database.commit()


        async with database.cursor() as cursor:

            add_otpSecret = pyotp.random_base32()

            query_Otp ='''INSERT INTO otp_table (username, otp_secret) VALUES (%s, %s)
                ON DUPLICATE KEY
                UPDATE otp_secret = IF(otp_secret IS NULL, VALUES(otp_secret), otp_secret)
                '''
            params_Otp = (username, add_otpSecret)

            await cursor.execute(query_Otp, params_Otp)

            row_count = cursor.rowcount

            if row_count == 0 :
                raise HTTPException(status_code=200, detail="Could not add username to the Reference table(otp_table)")
            
            await database.commit()

        return {"stat": 'Ok', "Result": "User created successfully"}

    except Exception as er:
        if not isinstance(er, HTTPException):
            logging.error(f"Error occured : {str(er)}")
            raise  HTTPException(500, detail="Internal Server Error")  
        else:
            raise 
    

async def create_user_standalone(username:str, email:str, hashed_password:str, 
                            db: DatabaseManager, role_id:int):
    
    try:
    
        query_Users = "INSERT INTO users (username, email, password, role_id) VALUES (%s, %s, %s, %s)"
        params_Users = (username, email, hashed_password, role_id)

        result = await db.execute_manipulation(query_Users, params_Users)

        if result == 1:
            return {"stat": 'Ok', "Result": "User created successfully"}
        else:
            return {"stat": 'Ok', "Result": "User creation failed!"}
    
    except Exception as er:
        if not isinstance(er, HTTPException):
            logging.error(f"Error occured : {str(er)}")
            raise  HTTPException(500, detail="Internal Server Error")  
        else:
            raise 

    
async def login_user_twoFA(username,secret, backgroudtasks:BackgroundTasks):

    try:
        otp_gen = pyotp.TOTP(secret)

        otp = otp_gen.now()

        '''Send this otp  to the user chosen medium of communication(otp sent as email or sms or both)
        but now, will include otp within the login reponse for testing purpose
        will change it later when notification feature is added.'''

        backgroudtasks.add_task(send_otp_email, username, otp)
        # await send_otp_email(recepient=username, otp=otp)

        return {'stat': 'Ok',"Result": "OTP sent to the registered mobile number/email"}  #, 'otp': otp
    
    except Exception as er:
        if not isinstance(er, HTTPException):
            logging.error(f"Error occured : {str(er)}")
            raise  HTTPException(500, detail="Internal Server Error")   
        else:
            raise 