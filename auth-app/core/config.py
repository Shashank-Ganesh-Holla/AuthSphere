import os
from dotenv import load_dotenv 
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer


class Config:
    load_dotenv()

    SECRET_KEY = os.getenv('SECRET_KEY')
    ALGORITHM = os.getenv('ALGORITHM')
    ACCESS_TOKEN_EXPIRE = int(os.getenv('ACCESS_TOKEN_EXPIRE'))
    REFRESH_TOKEN_EXPIRE = int(os.getenv('REFRESH_TOKEN_EXPIRE'))
    
    # Set up password hashing context
    context = CryptContext(schemes=['sha256_crypt'], deprecated = "auto")

    oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")