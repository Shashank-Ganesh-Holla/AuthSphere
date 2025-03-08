from typing import Dict
from auth_app.utils import DatabaseManager, TokenFactory
from fastapi import HTTPException, status, Depends, Request
import logging
from datetime import datetime

from abc import ABC, abstractmethod
from auth_app.utils import TokenManager

# ! Factory pattern implemented !
class UserManager:
    
    """Handles user-related operations, such as querying user data and handling user actions."""

    @staticmethod
    async def user_query(username) -> Dict:

        try:

            """Queries the database for a user by username."""

            query = "SELECT * FROM users WHERE username = %s"
            param = (username,)

            async with DatabaseManager() as db:
                user = await db.execute_read(query, param)   

            if user is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, 
                                                detail="User not found")
            return user
        
        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured : {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")   
            else:
                raise 
    
    @staticmethod
    async def get_current_user(user: str = Depends(TokenFactory.validate_token)):

        try:

            """Retrieves the current user based on the validated token."""

            username = user[0]

            user = await UserManager.user_query(username)

            if user is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, 
                                                detail="User not found")    
            return user
        
        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured : {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")   
            else:
                raise 
    
    @staticmethod
    async def logout_user(username, request:Request):
        
        try:
            from auth_app.core import websocket_manager

            """Logs out a user by blacklisting their current token."""

            token : str = await TokenFactory.get_token_from_request(request=request)

            if token is None:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token is required")
            
            logout_action = LogoutUserAction(username, token)

            result = await logout_action.action()
            
            #Websocket broadcast
            await websocket_manager.broadcast(f"{datetime.now()} : User: {username}, Result: Logout Success!")
            
            return result
        
        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured : {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")   
            else:
                raise 
    
    @staticmethod
    async def delete_user(username, request:Request):

        try:

            """Deletes a user from the database and blacklists their token."""
            
            token : str = await TokenFactory.get_token_from_request(request=request)

            if token is None:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token is required")

            delete_action = DeleteUserAction(username, token)

            result =  await delete_action.action()
            return result

        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured : {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")   
            else:
                raise



# ! Command pattern !
class UserAction(ABC):
    
    """Abstract class representing a user action (command pattern).
    
    This class defines a common interface for user actions, such as
    deleting or logging out, that must be implemented by subclasses.
    """

    @abstractmethod
    def action(self):

        try:

            """Executes the specified user action."""
            pass

        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured : {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")   
            else:
                raise  


class DeleteUserAction(UserAction):

    """Executes the action of deleting a user from the database."""

    def __init__(self, user, token):

        try:

            """Initializes with the target user's username and token."""

            self.user :str = user
            self.token : str = token

        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured : {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")   
            else:
                raise  


    async def action(self):

        try:

            """Deletes the user from the database and blacklists the token."""

            await UserManager.user_query(self.user)

            delete_query = "DELETE FROM users WHERE username = %s"
            delete_param = (self.user,)

            async with DatabaseManager() as db:
                result = await db.execute_manipulation(delete_query, delete_param)

            if result == 1:

                user = {'stat': 'Ok',
                        'Result': "User deleted Successfully!"}
                
                if self.token and isinstance(self.token, str) and self.token is not None:
                    await TokenManager.blacklist_token(self.user, self.token)

            else:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, 
                                            detail=f"Could not delete user:{self.user}")
            return user
        
        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured : {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")   
            else:
                raise  

class LogoutUserAction(UserAction):

    """Executes the action of logging out a user by blacklisting their token."""

    def __init__(self, user, token):

        try:

            """Initializes with the target user's username and token."""

            self.user = user
            self.token = token

        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured : {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")   
            else:
                raise  

    async def action(self):

        try:

            """Logs out the user by blacklisting their token."""

            await UserManager.user_query(self.user)

            if self.token and isinstance(self.token, str) and self.token is not None:
                await TokenManager.blacklist_token(self.user, self.token)

                user = {'stat': 'Ok',
                        'Result': "User logged out successfully!"}
            else:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, 
                                            detail=f"Logout failed for:{self.user}")
            return user 
        
        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured : {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")   
            else:
                raise


class UserRole:
    def __init__(self, role_name: str, user: str):
        self.role_name = role_name
        self.user = user 