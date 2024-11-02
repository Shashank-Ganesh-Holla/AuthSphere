import os
from dotenv import load_dotenv 
from fastapi import HTTPException, status
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer


class Config:
    load_dotenv()

    SECRET_KEY = os.getenv('SECRET_KEY')
    ALGORITHM = os.getenv('ALGORITHM')
    ACCESS_TOKEN_EXPIRE = int(os.getenv('ACCESS_TOKEN_EXPIRE'))
    REFRESH_TOKEN_EXPIRE = int(os.getenv('REFRESH_TOKEN_EXPIRE'))

    CREDENTIALS_EXCEPTION = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
                                          detail="Token expired, Please login again",
                                          headers={"WWW-Authenticate":"Bearer"})
    
    # Set up password hashing context
    context = CryptContext(schemes=['sha256_crypt'], deprecated = "auto")

    oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")