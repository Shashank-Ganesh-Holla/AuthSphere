from datetime import datetime, timedelta, timezone
import logging
from auth_app.core import config
from fastapi import HTTPException, status, Depends, Request
from jose import jwt, JWTError
from typing import Optional, Dict
from .db_connection import DatabaseManager

# oauth2_scheme=OAuth2PasswordBearer(tokenUrl="/login")

# ! Factory pattern implemented !

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
        import jwt as jt

        """Verifies and decodes a given JWT token."""

        try:
            payload = jwt.decode(token, config.SECRET_KEY, config.ALGORITHM)
            return payload
        
        except jt.exceptions.ExpiredSignatureError:
            logging.warning('Token has expired')
            raise HTTPException(status_code=401, detail="Token has expired", 
                                headers={"WWW-Authenticate":"Bearer"})
        
        except jt.exceptions.InvalidTokenError:
            logging.warning('Invalid token')
            raise HTTPException(status_code=401, detail="Invalid token",
                                 headers={"WWW-Authenticate":"Bearer"})
        
        except JWTError as e:
            logging.warning(str(e))
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"{str(e)}",
                                headers={"WWW-Authenticate":"Bearer"})
    
        except Exception as err:
            if not isinstance(err, HTTPException):
                logging.error(f"Error occured: {str(err)}")
                raise HTTPException(status_code=401, detail=f"{str(err)}", headers={"WWW-Authenticate":"Bearer"})
            else:
                raise
        

    @staticmethod
    async def validate_token(token:str = Depends(config.oauth2_scheme))->Optional[tuple[str, str]]:

        """Validates a token by checking its payload and blacklist status."""

        try:

            result = await TokenManager.is_token_blacklisted(token)

            if result and token == result.get('token'):
                logging.warning("User already logged out. Please re-login")
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="User logged out. Please re-login")
            
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

 