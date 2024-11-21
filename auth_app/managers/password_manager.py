from fastapi import HTTPException
from auth_app.core import config
import logging


#Factory pattern
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
            result =  config.context.verify(plain_password, hashed_password)

            return result
        
        except ValueError:
            # Handle the specific ValueError exception (invalid password) and return None
            logging.warning("Invalid password.")
            return None
        
        except Exception as er:
            
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured : {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")   
            else:
                raise  