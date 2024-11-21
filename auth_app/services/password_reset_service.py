from auth_app.repositories import UserRepository
from auth_app.utils import get_db_connection
from fastapi import Depends, HTTPException, status
import logging



async def get_password_reset_service(db =Depends(get_db_connection)):
    try:
        user_repo = UserRepository(db)
        return PasswordResetService(user_repo=user_repo)

    except Exception as err:
        logging.error(str(err))
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal Server Error")



class PasswordResetService:

    def __init__(self, user_repo:UserRepository):
        self.user_repo = user_repo


    async def request_password_reset(self, username, email):
        try:
            result = await self.user_repo.request_password_reset(username=username, email=email)
            return result


        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured: {str(er)}")
                raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")
            else:
                raise

    
    async def reset_password(self, token):
        
        try:
            result = await self.user_repo.reset_password(token=token)
            return result


        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured: {str(er)}")
                raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")
            else:
                raise

    async def submit_password(self, token, new_password):

        try:
            result = await self.user_repo.submit_password(token=token, new_password=new_password)
            return result


        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured: {str(er)}")
                raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")
            else:
                raise


    