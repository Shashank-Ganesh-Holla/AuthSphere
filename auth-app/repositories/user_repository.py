from fastapi import HTTPException, status
from utils import create_user_table_batch, create_user_standalone, login_user_twoFA, TokenFactory, DatabaseManager
from managers import PasswordManager
import logging
import aiomysql
import pyotp
from core import websocket_manager
from datetime import datetime
import pyotp
import secrets
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import os
import pytz

# Set the time zone to Asia/Kolkata
kolkata_tz = pytz.timezone('Asia/Kolkata')

# Get the current time in UTC and convert it to Asia/Kolkata time zone
now_utc = datetime.now(pytz.utc)
now_kolkata = now_utc.astimezone(kolkata_tz)

now = now_kolkata.strftime("%Y-%m-%d %H:%M:%S")
# Add 10 minutes
now_plus_10 = now_kolkata + timedelta(minutes=10)


load_dotenv()

class UserRepository:
    
    def __init__(self, db:DatabaseManager):
        self.db = db
 



    async def __get_column_any_table(self, table:str, column:str, condition:str, condition_value:str):
        try:
            query = f"SELECT {column} FROM {table} WHERE {condition} = %s"
            result =  await self.db.execute_read(query, (condition_value,))
            return result
        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured: {str(er)}")
                raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")
            else:
                raise



    async def __get_user_any_table(self, table:str, username:str):
        try:
            query = f"SELECT * FROM {table} WHERE username = %s"
            result =  await self.db.execute_read(query, (username,))
            return result
        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured: {str(er)}")
                raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")
            else:
                raise


    async def __get_user_users_table(self, username:str):

        try:
            query = "SELECT * FROM users WHERE username = %s"
            result =  await self.db.execute_read(query, (username,))
            return result
        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured: {str(er)}")
                raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")
            else:
                raise
    
    async def __get_user_otp_table(self, username:str):

        try:
            query = "SELECT * FROM  otp_table WHERE username = %s"
            result =  await self.db.execute_read(query, (username,))
            return result
        
        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured: {str(er)}")
                raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")
            else:
                raise
    
    
    async def __manipulate_users_table(self, operation:str, query, *args, **kwargs):

        """Args:
            operation (str): The type of operation (e.g., 'insert', 'update').
            query (str): The query to manipulate the users table.
            *args (Any): Optional positional arguments, can vary based on the operation.
            **kwargs (Any): Keyword arguments, can vary based on the operation.
        """
        try:

            if operation in ['update_from_login', "update_twoFa"]:

                new_state = kwargs.get('new_state', False)
                current_state = kwargs.get('current_state', True)
                username = kwargs.get('username', '')

                params = (new_state, username, current_state)

                result = await self.db.execute_manipulation(query=query, params=params)


                if operation == "update_from_login":
                    raise HTTPException(status.HTTP_404_NOT_FOUND, 
                                    detail=f'''OTP data not found for user: {kwargs.get('username', '')}, Please try login again!''')
                
                return result
                
            elif operation == 'update_otpTable_twoFa':
                params = (kwargs.get('otpSecret'), kwargs.get('username', ''))

                result = await self.db.execute_manipulation(query=query, params=params)

            elif operation == 'update_from_reqPaswdReset':
                
                username = kwargs.get('username')
                token = kwargs.get('token')
                expiration = kwargs.get('expiration')

                params = (token, expiration, username)

                result = await self.db.execute_manipulation(query=query, params=params)

                return result
            
            elif operation == 'create_from_reqPaswdReset':

                username = kwargs.get('username')
                token = kwargs.get('token')
                expiration = kwargs.get('expiration')

                params = (username, token, expiration)

                result = await self.db.execute_manipulation(query=query, params=params)

                return result
            
            elif operation == 'submit_password':

                user = kwargs.get('username')
                new_password = kwargs.get('password')

                params = (new_password, user, new_password)

                result = await self.db.execute_manipulation(query=query, params=params)

                return result

        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured: {str(er)}")
                raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")
            else:
                raise


    async def create_user(self, username:str, email:str, password:str, two_fa:bool, database:aiomysql.Connection):

        '''the self.db instance is the instance of DataBaseManager context manager which has commit() within'''

        '''This method will also have standalone instance of connection from create_connection() injected into 'database' parameter
        which will be used for batch Transaction into database tables'''

        try:

            user_in_otp_table = await self.__get_user_otp_table(username)

            if user_in_otp_table:

                '''Here, the databsae connection param is 'db' which is a DatabaseManager object (context manager)'''

                result =  await create_user_standalone(username=username, email=email,
                                        hashed_password=password,two_fa=two_fa,db=self.db)
                                        
                #Websocket broadcast
                await websocket_manager.broadcast(f"{datetime.now()} : User: {username}, Result: {username} successfully created!")
                return result
            
            else:
                
                '''Here, the databsae connection param is 'database' which is referenced from the dependency function 
                from the endpoint or path function signature i.e.,

                async def register(user:UserCreate, 
                   auth_service:AuthService = Depends(get_auth_service), 
                   db:aiomysql.Connection = Depends(get_db_connection_batch_process) ):
                   .............'''
                
                result =  await create_user_table_batch(username=username, email=email,
                                        hashed_password=password,two_fa=two_fa, database=database)

                #Websocket broadcast
                await websocket_manager.broadcast(f"{datetime.now()} : User: {username}, Result: {username} successfully created!")
                return result 
        
        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured: {str(er)}")
                raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")
            else:
                raise        
    
    async def login_user(self, username, password, backgroudtasks):

        try:
            user_exists = await self.__get_user_users_table(username)

            if user_exists and PasswordManager.verify_password(plain_password=password,hashed_password=user_exists.get('password')):
                
                if user_exists.get('twofa_status'):
                    '''For user who have enabled twofa(password and otp)'''

                    user_otp_details = await self.__get_user_otp_table(username)

                    if user_otp_details.get('otp_secret'):

                        '''Ensuring 'otp_secret' column from otp_table is not Null'''

                        secret = user_otp_details.get('otp_secret')
                        result =  await login_user_twoFA(username=username, secret=secret, backgroudtasks=backgroudtasks)

                        #Websocket broadcast
                        await websocket_manager.broadcast(f"{datetime.now()} : User: {username}, Result: OTP sent to the registered email/mobile number")

                        return result
                    
                    else:
                        '''Reset the twofa as disabled and ask to relogin as the otp_secrt data for the user not found in database.
                        Can be set with "/update_twofa" endpoint once the user login with password'''

                        update_false = "UPDATE users SET twofa_status = %s WHERE username = %s AND twofa_status = %s"
                        current_state = True 
                        new_state = False
                        
                        await self.__manipulate_users_table("update_from_login",update_false, username = username ,current_state = current_state, new_state = new_state)

                else:
                    '''For users with only password authentication'''
                    data = {"sub":username, 'role': user_exists.get('role_id')}
                    access_token = TokenFactory.create_access_token(data=data)
                    refresh_token = TokenFactory.create_refresh_token(data=data)

                    #Websocket broadcast
                    await websocket_manager.broadcast(f"{datetime.now()} : User: {username}, Result: Login Success!")

                    return {"access_token": access_token, "refresh_token": refresh_token ,"token_type":"bearer"}
                    


            else:
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid username or Password")

        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured : {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")    
            else:
                raise 


    async def verify_otp_user(self, username, otp):

        try:

            user_exists = await self.__get_user_users_table(username)

            otp_details = await self.__get_user_otp_table(username)

            if user_exists and otp_details :
                is_valid = pyotp.TOTP(otp_details.get('otp_secret')).verify(otp, valid_window=1)

                if is_valid:
                
                    data = {'sub': otp_details.get('username'), 'role': user_exists.get('role_id')}

                    access_token = TokenFactory.create_access_token(data)
                    refresh_token = TokenFactory.create_refresh_token(data=data)

                    #Websocket broadcast
                    await websocket_manager.broadcast(f"{datetime.now()} : User: {username}, Result: OTP verification successful")

                    return {"access_token": access_token, "refresh_token": refresh_token ,"token_type":"bearer"}
                
                else:
                    logging.error("Invalid OTP")
                    raise HTTPException(status.HTTP_401_UNAUTHORIZED,detail="Invalid OTP")

            logging.error("Invalid user details")    
            raise HTTPException(status.HTTP_400_BAD_REQUEST,detail="Invalid user details")
            
        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured : {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")
            
            else:
                raise 

    async def update_twoFa(self, username, twoFA_enabled):

        try:
            if not twoFA_enabled:
                '''when twofa_status param is False'''
                # here we just need to update the twofa_status column of users table as False

                false_query = "UPDATE users SET twofa_status = %s WHERE username = %s AND twofa_status = %s"
                current_state = True
                new_state = False
                result = await self.__manipulate_users_table("update_twoFa",false_query, username = username ,current_state = current_state, new_state = new_state)
                
                if result == 1:
                    return {"stat": "Ok", "Result": f"twoFA disabled successfully for {username}"}
                
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="twoFA already disabled")
            
            else:
                '''when twofa_status param is True'''

                '''There are two things to do in this condition:

                    1. check if the otp_secret in otp_table for the username is not None,
                        if None then create a otpsecret and update, if not None then as is'''
                
                otp_scrt_query = "UPDATE otp_table SET otp_secret = %s WHERE username = %s AND otp_secret IS NULL"
                add_otpSecret = pyotp.random_base32()
        
                result = await self.__manipulate_users_table("update_otpTable_twoFa",otp_scrt_query, username = username ,otpSecret = add_otpSecret)

                
                '''2. update the twofa_status column, checking if its already True, if not then update'''

                true_query = "UPDATE users SET twofa_status = %s WHERE username = %s AND twofa_status = %s"
                current_state = False
                new_state = True

                result = await self.__manipulate_users_table("update_twoFa",true_query, username = username ,
                                                        current_state = current_state,
                                                        new_state = new_state)
                if result == 1:
                    return {"stat": "Ok", "Result": f"twoFA enabled successfully for {username}"}
                
                elif result == None:
                    logging.error("Error from database: result returned None")
                    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error") 
                
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="twoFA already enabled")
            
        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured : {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")    
            else:
                raise


    async def request_password_reset(self, username, email):

        query = '''SELECT * FROM users WHERE username = %s AND email = %s'''
        params = (username, email)
        user_exists = await self.db.execute_read(query, params)

        if not user_exists:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="username/email not found")

        is_reset_user = await self.__get_user_any_table(table='password_reset_tokens', username=username)

        token = secrets.token_urlsafe(32)
        expiration = now_plus_10
        # expiration = datetime.now(timezone.utc) + timedelta(minutes=10)


        if not is_reset_user:
            query = ''' INSERT INTO password_reset_tokens (username, token, expiration) VALUES (%s,%s,%s)'''

            resp = await self.__manipulate_users_table("create_from_reqPaswdReset",query, username = username, token= token, expiration = expiration)
            
        else:

            query = '''UPDATE password_reset_tokens 
                    SET token = %s,
                    expiration = %s
                    WHERE username = %s;
                '''
            resp = await self.__manipulate_users_table("update_from_reqPaswdReset",query, username = username, token= token, expiration = expiration)
        

       
        if resp == 1:
            result = {"url_link": f"http://{os.getenv('HOST')}:{os.getenv('PORT')}/reset/reset-password?token={token}"}

            return result
        
        else:
            raise HTTPException(status.HTTP_409_CONFLICT, detail="Password Reset failed, Please try again!") 


    async def __check_reset_token(self, token, column=None, condition = None, condition_value=None, table = None):

        table =  table if table is not None else 'password_reset_tokens'
        column =  column if column is not None else 'expiration'
        condition = condition if condition is not None else 'token'
        condition_value = condition_value if condition_value is not None else token

        result = await self.__get_column_any_table(table=table,column=column,
                                                           condition=condition, condition_value=condition_value)

        if not result:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Token error, please try again")
        
        return result



    async def reset_password(self, token):

        try:
            expiration = await self.__check_reset_token(token)

            expiration_from_table = expiration.get('expiration').strftime("%Y-%m-%d %H:%M:%S")

            if now < expiration_from_table:
                return True
            else:
                raise HTTPException(status_code=400, detail="Token has expired.")
            
        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured : {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")    
            else:
                raise

        


    async def submit_password(self, token, new_password):

        try:

            is_reset_token = await self.__check_reset_token(token, column='*')

            expiration = is_reset_token.get('expiration').strftime("%Y-%m-%d %H:%M:%S")

            if now >= expiration:
                raise HTTPException(status_code=400, detail="Token has expired.")


            user = is_reset_token.get('username')

            is_password_same = await self.__get_user_users_table(username=user)

            current_password = is_password_same.get('password')

            if PasswordManager.verify_password(plain_password=new_password,hashed_password=current_password):
                return {"stat": "Not_Ok", 
                        "Result": "The new password cannot be the same as your previous password. Please choose a different password."}



            query = '''UPDATE users 
                    SET password = %s
                    WHERE username = %s AND password != %s;
                '''
            


            result = await self.__manipulate_users_table("submit_password",query, username = user ,password = new_password)

            if result == 1:
                return {"stat": "Ok", "Result": "Password reset successful."}
            else:
                return {"stat": "Not_Ok", "Result": "Not able to update password"}
            

        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured : {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")    
            else:
                raise

        

       
