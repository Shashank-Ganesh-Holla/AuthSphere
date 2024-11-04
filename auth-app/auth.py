from fastapi import HTTPException, status, Depends, Request
from datetime import timedelta, datetime
from jose import jwt, JWTError
import jwt as jt
from core.config import Config
from database import create_connection, execute_read_query, execute_write_query
from abc import ABC, abstractmethod
from typing import Dict, Optional
import logging

# ! Context manager pattern !
class DatabaseManager:
    """Context manager to handle database connections.
    
    Establishes and closes database connections automatically
    and provides methods to execute read and write queries.
    """

    def __enter__(self):
        """Creates a database connection when entering the context."""
        self.connection = create_connection()
        return self
    

    def __exit__(self, error_type, error_value, error_traceback):
        """Closes the database connection when exiting the context."""
        if self.connection: self.connection.close()


    def execute_read(self, query, params):
        """Executes a read query on the database."""        
        return execute_read_query(self.connection, query, params)
    
    
    def execute_manipulation(self, query, params):
        """Executes a write (manipulation) query on the database."""
        return execute_write_query(self.connection,query, params)



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
            expire = datetime.utcnow() + timedelta(minutes = Config.ACCESS_TOKEN_EXPIRE)
            
            # make sure the key you are using is 'exp' not any customized, if you want to add customized key then convert it to timestamp
            # because "exp" is by default key name for the timestamp format and jwt accepts only timestamp format not datetime
            to_encrypt.update({"exp":expire, "type": "access"})

            encoded_jwt = jwt.encode(to_encrypt,Config.SECRET_KEY,Config.ALGORITHM)
            return encoded_jwt

        except Exception as err:
            logging.error(str(err))
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err))
        
    @staticmethod
    def create_refresh_token(data:dict):

        """Creates a refresh token with a longer expiration time for user sessions."""

        try:
            to_encrypt = data.copy()
            expire = datetime.utcnow() + timedelta(days = Config.REFRESH_TOKEN_EXPIRE)
            
            # make sure the key you are using is 'exp' not any customized, if you want to add customized key then convert it to timestamp
            # because "exp" is by default key name for the timestamp format and jwt accepts only timestamp format not datetime
            to_encrypt.update({"exp":expire, "type": "refresh"})

            encoded_jwt = jwt.encode(to_encrypt,Config.SECRET_KEY,Config.ALGORITHM)
            return encoded_jwt

        except Exception as err:
            logging.error(str(err))
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err))
    

    @staticmethod
    def verify_token(token:str):

        """Verifies and decodes a given JWT token."""

        try:
            payload = jwt.decode(token, Config.SECRET_KEY, Config.ALGORITHM)
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
            logging.error(str(err))
            raise HTTPException(status_code=401, detail=f"{str(err)}", headers={"WWW-Authenticate":"Bearer"})
        
    @staticmethod
    def validate_token(token:str = Depends(Config.oauth2_scheme))->Optional[tuple[str, str]]:

        """Validates a token by checking its payload and blacklist status."""

        try:

            result = TokenManager.is_token_blacklisted(token)

            if result and token == result.get('token'):
                logging.error("User already logged out. Please re-login")
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="User already logged out. Please re-login")
            
            # verify the token
            payload = TokenFactory.verify_token(token)
            
            return payload.get('sub', ''), payload.get('role', '')
        
        except Exception as err:

            if not isinstance(err ,HTTPException):
                logging.error(f"An error occured {str(err)}")
                raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
            else:
                raise


    @staticmethod
    async def get_token_from_request(request:Request):

        """Extracts the token from the request header."""

        return await Config.oauth2_scheme(request)

class TokenManager:

    """Manages token blacklist operations.
    
    Supports checking if a token is blacklisted and blacklisting tokens
    to prevent reuse after logout.
    """

    @staticmethod
    def blacklist_token(username:str, token:str):

        """Adds a token to the blacklist to prevent its reuse."""

        with DatabaseManager() as db:

            query = "INSERT INTO token_blacklist (username, token) VALUES(%s, %s)"
            params = (username, token)

            db.execute_manipulation(query,params)

    @staticmethod
    def is_token_blacklisted(token: str) -> Optional[Dict]:

        """Checks if a token exists in the blacklist."""

        with DatabaseManager() as db:

            query = "SELECT * FROM token_blacklist WHERE token = %s"
            params = (token,)

            result = db.execute_read(query, params)
            
            return result

class UserManager:

    """Handles user-related operations, such as querying user data and handling user actions."""

    @staticmethod
    def user_query(username) -> Dict:

        """Queries the database for a user by username."""

        user = None 
        query = "SELECT * FROM users WHERE username = %s"
        param = (username,)

        with DatabaseManager() as db:
            user = db.execute_read(query, param)   

        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, 
                                            detail="User not found")
        return user
    
    @staticmethod
    def get_current_user(user: str = Depends(TokenFactory.validate_token)):

        """Retrieves the current user based on the validated token."""

        username = user[0]

        user = UserManager.user_query(username)

        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, 
                                            detail="User not found")
        
        return user
    
    @staticmethod
    async def logout_user(username, request:Request):

        """Logs out a user by blacklisting their current token."""

        token = await TokenFactory.get_token_from_request(request=request)
        
        logout_action = LogoutUserAction(username, token)

        return logout_action.action()
    
    @staticmethod
    async def delete_user(username, request:Request):

        """Deletes a user from the database and blacklists their token."""
        
        token = await TokenFactory.get_token_from_request(request=request)

        delete_action = DeleteUserAction(username, token)

        return delete_action.action()

class RoleManager:

    """Manages user roles and access permissions."""

    @staticmethod
    def get_user_role(role:str = Depends(TokenFactory.validate_token)):

        """Determines the role of the current user based on the token."""

        role_id = role[1] 

        if role_id == 1:
            role_name = 'admin'

        elif role_id == 2:
            role_name = 'user'
            
        else:
            role_name = ''
        
        return role_name

    @staticmethod
    def role_required(required_role:str):

        """Defines a role requirement check for specific resources."""
        
        '''A closure function used here that helps in calling an inner function and accessing the params of outer function
        even after the outer function is completely executed. FastAPI will execute the returned check_user_role function 
        even though () is not suffixed to it.'''

        def check_user_role(user_role : str  = Depends(RoleManager.get_user_role)):
            if required_role != user_role:
                raise HTTPException(status.HTTP_403_FORBIDDEN, detail = "You don't have permission to access this resource")
            
            return True

        return check_user_role

class PasswordManager:
     
    """Handles password hashing and verification using secure hashing algorithms."""

    @staticmethod
    def hash_password(password: str) -> str:

        """Hashes a plain password for secure storage."""

        return Config.context.hash(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:

        """Verifies a plain password against its hashed counterpart."""

        return Config.context.verify(plain_password, hashed_password)



# ! Command pattern !
class UserAction(ABC):
    
    """Abstract class representing a user action (command pattern).
    
    This class defines a common interface for user actions, such as
    deleting or logging out, that must be implemented by subclasses.
    """

    @abstractmethod
    def action(self):

        """Executes the specified user action."""

        pass

class DeleteUserAction(UserAction):

    """Executes the action of deleting a user from the database."""

    def __init__(self, user, token):

        """Initializes with the target user's username and token."""

        self.user = user
        self.token = token


    def action(self):

        """Deletes the user from the database and blacklists the token."""

        try:
            UserManager.user_query(self.user)

            delete_query = "DELETE FROM users WHERE username = %s"
            delete_param = (self.user,)

            with DatabaseManager() as db:
                result = db.execute_manipulation(delete_query, delete_param)

            if result == 1:

                user = {'stat': 'Ok',
                        'Result': f"'user deleted Successfully!"}
                
                if self.token and isinstance(self.token, str):
                    TokenManager.blacklist_token(self.user, self.token)

            else:
                raise HTTPException(status_code=status.HTTP_200_OK, 
                                            detail=f"Could not delete user:{self.user}")
            return user
        
        except Exception as err:

            if not isinstance(err, HTTPException):
                logging.error(str(err))
                raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail = "Internal server error")
            else:
                raise

class LogoutUserAction(UserAction):

    """Executes the action of logging out a user by blacklisting their token."""

    def __init__(self, user, token):

        """Initializes with the target user's username and token."""

        self.user = user
        self.token = token

    def action(self):

        """Logs out the user by blacklisting their token."""

        try:
            UserManager.user_query(self.user)

            if self.token and isinstance(self.token, str):
                TokenManager.blacklist_token(self.user, self.token)

                user = {'stat': 'Ok',
                        'Result': f"Logout success!"}
            else:
                raise HTTPException(status_code=status.HTTP_200_OK, 
                                            detail=f"Logout failed for:{self.user}")
            return user 
        
        except Exception as err:
            if not isinstance(err, HTTPException):
                logging.error(str(err))
                raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail = "Internal server error")
            else:
                raise

