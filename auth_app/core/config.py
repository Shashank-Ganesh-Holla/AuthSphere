# from pydantic import field_validator
# from pydantic_settings import BaseSettings
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from typing import ClassVar, List
import logging
from fastapi import WebSocket
from fastapi.templating import Jinja2Templates
# from dotenv import load_dotenv
import os

# Load environment variables from the .env file
# load_dotenv()  # This loads the .env file manually

class Logger:

    @staticmethod
    def setup_logging():
        logging.basicConfig(
            filename='../logs/app.log',
            filemode='a',
            level=logging.INFO,
            format='\n%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - Details: %(message)s ',
        )


class Config:
    """Custom Configuration class for managing application settings."""

    # Environment variables with default fallbacks
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your_default_secret")
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE: int = int(os.getenv("ACCESS_TOKEN_EXPIRE", 10))
    REFRESH_TOKEN_EXPIRE: int = int(os.getenv("REFRESH_TOKEN_EXPIRE", 1))

    # Set up password hashing context
    context = CryptContext(schemes=["sha256_crypt"], deprecated="auto")

    # Jinja2 Templates
    templates = Jinja2Templates(directory="auth-app/templates")

    # OAuth2 Scheme
    oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


# class Config(BaseSettings):
#     """Configuration class that loads environment variables automatically."""

#     SECRET_KEY: str
#     ALGORITHM: str
#     ACCESS_TOKEN_EXPIRE: int = 10
#     REFRESH_TOKEN_EXPIRE: int = 1


    
#     # Set up password hashing context
#     context: ClassVar[CryptContext] =CryptContext(schemes=['sha256_crypt'], deprecated="auto")
    
#     templates: Jinja2Templates = Jinja2Templates(directory="auth-app/templates")

#     oauth2_scheme : ClassVar[OAuth2PasswordBearer] = OAuth2PasswordBearer(tokenUrl="/login")

#     # Inner `Config` class to configure how settings are loaded (e.g., from a `.env` file)
#     class Config:
#         env_file: ClassVar[str] = ".env"
#         extra: ClassVar[str] = "allow"
#         env_file_encoding: ClassVar[str] = 'utf-8'


#     @field_validator('ACCESS_TOKEN_EXPIRE', 'REFRESH_TOKEN_EXPIRE')
#     def check_integers(cls, value):
#         if value == '':
#             return 3600  # Default to 3600 if empty
#         return int(value)



class WebsocketManager:

    def __init__(self):
        
        self.connections : List[WebSocket] = [] # Connection pool
        self.message_queue = []  # message queue

    async def connect(self, websocket:WebSocket):

        await websocket.accept()
        self.connections.append(websocket)

        await websocket.send_text("Queued messages(Last 10)")

        for message in self.message_queue[-10:]:
            await websocket.send_text(message)

    async def broadcast(self, message):

        self.message_queue.append(message)

        if len(self.message_queue) > 100:
            self.message_queue.pop(0)

        for connection in self.connections:
            try:
                await connection.send_text(message)
            except RuntimeError as e:
                logging.warning(f"Removing closed connection due to error: {e}")
                await self.disconnect(connection)  # Close and remove from pool

    
    async def disconnect(self, websocket:WebSocket):
        try:
            await websocket.close()
            self.connections.remove(websocket)
        except RuntimeError as e:
            return
        



config = Config()
websocket_manager = WebsocketManager()
# print(config.SECRET_KEY)