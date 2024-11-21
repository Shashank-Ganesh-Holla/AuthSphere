from auth_app.repositories import UserRepository
from auth_app.utils import get_db_connection
from fastapi import Depends, HTTPException, status
import logging
from auth_app.managers import UserManager



async def get_user_service(db =Depends(get_db_connection)):
    try:
        user_repo = UserRepository(db)
        return UserService(user_repo=user_repo)

    except Exception as err:
        logging.error(str(err))
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal Server Error")
    



class UserService:
    
    def __init__(self, user_repo:UserRepository):
        self.user_repo = user_repo


    async def get_user_details(self, username):

        try:
            result = await self.user_repo.get_user_details(username=username)
            return result


        except Exception as err:
            if not isinstance(err, HTTPException):
                logging.error(f"Error occured : {str(err)}")
                raise  HTTPException(500, detail="Internal Server Error")    
            else:
                raise
        

    async def delete_user_me(self, request, username):

        try:
            user = await UserManager.delete_user(username=username, request=request)
            return user


        except Exception as err:
            if not isinstance(err, HTTPException):
                logging.error(f"Error occured : {str(err)}")
                raise  HTTPException(500, detail="Internal Server Error")    
            else:
                raise

    async def assign_role(self, username, role_name):

        try:
            result = await self.user_repo.assign_role(username=username, role_name = role_name)
            return result


        except Exception as err:
            if not isinstance(err, HTTPException):
                logging.error(f"Error occured : {str(err)}")
                raise  HTTPException(500, detail="Internal Server Error")    
            else:
                raise