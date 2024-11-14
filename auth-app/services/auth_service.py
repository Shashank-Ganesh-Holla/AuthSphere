from repositories import UserRepository
from fastapi import HTTPException, Request
from managers import PasswordManager
from managers import UserManager
import logging
import aiomysql
from fastapi import Depends, status
from utils import get_db_connection


async def get_auth_service(db = Depends(get_db_connection)):
    try:
        user_repository = UserRepository(db)
        return AuthService(user_repo=user_repository)
    
    except Exception as err:
        logging.error(str(err))
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal Server Error")
    

    

class AuthService:
    
    def __init__(self, user_repo:UserRepository):
        self.user_repo = user_repo

    async def register_user(self, username:str, email:str, password: str, 
                            db:aiomysql.Connection,
                            role_id:int = 2,
                            two_fa:bool = False):
        try:
            hashed_Password = PasswordManager.hash_password(password)

            result = await self.user_repo.create_user(username=username,email=email,
                                                      password=hashed_Password, database = db,
                                                      role_id=role_id, two_fa=two_fa)
            
            return result
        
        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured : {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")   
            else:
                raise 
        


    async def login(self, backgroudtasks, username:str, password:str):

        try:
            result = await self.user_repo.login_user(username=username, password=password, backgroudtasks=backgroudtasks)
            return result
        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured: {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")
            raise 

    
    async def otp_verify(self, username:str, otp:str):

        try:
            result = await self.user_repo.verify_otp_user(username=username, otp=otp)
            return result
        
        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured: {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")
            raise 
        



    async def logout(self, request:Request, 
                      username:str):
        try:
            user = await UserManager.logout_user(username, request)
            return user 
        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured: {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")
            raise



    async def update_twoFa(self, 
                      username:str,twoFA_enabled):
        try:
            user = await self.user_repo.update_twoFa(username, twoFA_enabled)
            return user 
        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured: {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")
            raise  
        