from pydantic_settings import BaseSettings
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from typing import ClassVar
import logging

class Logger:

    @staticmethod
    def setup_logging():
        logging.basicConfig(
            filename='logs/app.log',
            filemode='a',
            level=logging.INFO,
            format='\n%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - Details: %(message)s ',
        )


class Config(BaseSettings):
    """Configuration class that loads environment variables automatically."""

    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE: int
    REFRESH_TOKEN_EXPIRE: int
    
    # Set up password hashing context
    context: ClassVar[CryptContext] =CryptContext(schemes=['sha256_crypt'], deprecated="auto")
    

    oauth2_scheme : ClassVar[OAuth2PasswordBearer] = OAuth2PasswordBearer(tokenUrl="/login")

    # Inner `Config` class to configure how settings are loaded (e.g., from a `.env` file)
    class Config:
        env_file = "/auth-app/.env"  # Specify the location of your environment file


config = Config()
# print(config.SECRET_KEY)