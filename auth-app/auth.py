from fastapi import HTTPException, status, Depends, Request
from datetime import timedelta, datetime, timezone
from jose import jwt, JWTError
import jwt as jt
from core import config
from database import create_connection, execute_read_query, execute_write_query
from abc import ABC, abstractmethod
from typing import Dict, Optional, AsyncGenerator
import logging
from contextlib import asynccontextmanager
from utils import DatabaseManager
from core import websocket_manager


# ! Factory pattern implemented !
class TokenFactory:

    """Factory class for generating and validating JWT tokens.
    
    Provides methods to create access and refresh tokens,
    verify tokens, and validate tokens.
    """

    
    @staticmethod
    def create_access_token(data:dict):

        """Creates an access token with an expiration time for user sessions."""
    
        try:
            to_encrypt = data.copy()
            expire = datetime.now(timezone.utc) + timedelta(minutes = config.ACCESS_TOKEN_EXPIRE)
            
            # make sure the key you are using is 'exp' not any customized, if you want to add customized key then convert it to timestamp
            # because "exp" is by default key name for the timestamp format and jwt accepts only timestamp format not datetime
            to_encrypt.update({"exp":expire, "type": "access"})

            encoded_jwt = jwt.encode(to_encrypt,config.SECRET_KEY,config.ALGORITHM)
            return encoded_jwt

        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured : {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")   
            else:
                raise

        
    @staticmethod
    def create_refresh_token(data:dict):

        """Creates a refresh token with a longer expiration time for user sessions."""

        try:
            to_encrypt = data.copy()
            expire = datetime.now(timezone.utc) + timedelta(days = config.REFRESH_TOKEN_EXPIRE)
            
            # make sure the key you are using is 'exp' not any customized, if you want to add customized key then convert it to timestamp
            # because "exp" is by default key name for the timestamp format and jwt accepts only timestamp format not datetime
            to_encrypt.update({"exp":expire, "type": "refresh"})

            encoded_jwt = jwt.encode(to_encrypt,config.SECRET_KEY,config.ALGORITHM)
            return encoded_jwt

        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured : {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")   
            else:
                raise 
    

    @staticmethod
    def verify_token(token:str):

        """Verifies and decodes a given JWT token."""

        try:
            payload = jwt.decode(token, config.SECRET_KEY, config.ALGORITHM)
            return payload
        
        except jt.ExpiredSignatureError:
            logging.error('Token has expired')
            raise HTTPException(status_code=401, detail="Token has expired", 
                                headers={"WWW-Authenticate":"Bearer"})
        
        except jt.InvalidTokenError:
            logging.error('Invalid token')
            raise HTTPException(status_code=401, detail="Invalid token",
                                 headers={"WWW-Authenticate":"Bearer"})
        
        except JWTError as e:
            logging.error(str(e))
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"{str(e)}",
                                headers={"WWW-Authenticate":"Bearer"})
    
        except Exception as err:
            if not isinstance(err, HTTPException):
                logging.error(str(err))
                raise HTTPException(status_code=401, detail=f"{str(err)}", headers={"WWW-Authenticate":"Bearer"})
            else:
                raise
        
    # lets try dependecy TokenManager.is_token_blacklisted injected into validate_token afterwards
    @staticmethod
    async def validate_token(token:str = Depends(config.oauth2_scheme))->Optional[tuple[str, str]]:

        """Validates a token by checking its payload and blacklist status."""

        try:

            result = await TokenManager.is_token_blacklisted(token)

            if result and token == result.get('token'):
                logging.error("User already logged out. Please re-login")
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="User already logged out. Please re-login")
            
            # verify the token
            payload = TokenFactory.verify_token(token)
            
            return payload.get('sub', ''), payload.get('role', '')
        
        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured : {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")   
            else:
                raise 


    @staticmethod
    async def get_token_from_request(request:Request):
        try:

            """Extracts the token from the request header."""
            result = await config.oauth2_scheme(request)
            return result
        
        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured : {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")   
            else:
                raise 
class TokenManager:

    """Manages token blacklist operations.
    
    Supports checking if a token is blacklisted and blacklisting tokens
    to prevent reuse after logout.
    """

    @staticmethod
    async def blacklist_token(username:str, token:str):

        try:

            """Adds a token to the blacklist to prevent its reuse."""

            async with DatabaseManager() as db:

                query = "INSERT INTO token_blacklist (username, token) VALUES(%s, %s)"
                params = (username, token)

                await db.execute_manipulation(query,params)

        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured : {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")   
            else:
                raise 


    @staticmethod
    async def is_token_blacklisted(token: str) -> Optional[Dict]:

        try:
            """Checks if a token exists in the blacklist."""

            async with DatabaseManager() as db:

                query = "SELECT * FROM token_blacklist WHERE token = %s"
                params = (token,)

                result = await db.execute_read(query, params)
                
                return result

        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured : {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")   
            else:
                raise 

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

class RoleManager:

    """Manages user roles and access permissions."""

    @staticmethod
    async def get_user_role(role:str = Depends(TokenFactory.validate_token)):

        try:

            """Determines the role of the current user based on the token."""

            role_id = role[1] 

            if role_id == 1:
                role_name = 'admin'

            elif role_id == 2:
                role_name = 'user'
                
            else:
                role_name = ''
            
            return role_name
        
        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured : {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")   
            else:
                raise 

    @staticmethod
    def role_required(required_role:str):

        try:

            """Defines a role requirement check for specific resources."""
            
            '''A closure function used here that helps in calling an inner function and accessing the params of outer function
            even after the outer function is completely executed. FastAPI will execute the returned check_user_role function 
            even though () is not suffixed to it.'''

            async def check_user_role(user_role : str  = Depends(RoleManager.get_user_role)):
                if required_role != user_role:
                    raise HTTPException(status.HTTP_403_FORBIDDEN, detail = "You don't have permission to access this resource")
                
                return True

            return check_user_role
    
        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured : {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")   
            else:
                raise 

class PasswordManager:
     
    """Handles password hashing and verification using secure hashing algorithms."""

    @staticmethod
    def hash_password(password: str) -> str:

        try:

            """Hashes a plain password for secure storage."""

            return config.context.hash(password)
        
        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured : {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")   
            else:
                raise 

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:

        try:
            """Verifies a plain password against its hashed counterpart."""
            return config.context.verify(plain_password, hashed_password)
        
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
