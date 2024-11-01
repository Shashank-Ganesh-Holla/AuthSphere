from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt
from database import create_connection, execute_read_query, execute_write_query
from fastapi import Request
import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv('SECRET_KEY')
ALGORITHM = os.getenv('ALGORITHM')
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES'))


CREDENTIALS_EXCEPTION = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
                                          detail="Token expired, Please login again",
                                          headers={"WWW-Authenticate":"Bearer"})

# Set up password hashing context
context = CryptContext(schemes=['sha256_crypt'], deprecated = "auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

def hash_password(password:str)-> str:
    return context.hash(password)


def verify_password(plain_password:str, hashed_password:str)-> bool:
    return context.verify(plain_password,hashed_password)



def create_access_token(data:dict):
    to_encrypt = data.copy()

    expire =datetime.utcnow()+timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encrypt.update({"exp":expire})

    encoded_jwt = jwt.encode(to_encrypt,SECRET_KEY,ALGORITHM)

    return encoded_jwt

def verify_access_token(token:str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
        return payload
    
    except JWTError:
        return None
    
def blacklist_token(username:str, token:str):
    connection = create_connection()

    query = "INSERT INTO token_blacklist (username, token) VALUES(%s, %s)"
    params = (username, token)

    result = execute_write_query(connection, query,params)

    connection.close()



def manipulate_user(username, token:str=None, delete = None, logout = None):

    connection = create_connection()
    query_1 = "SELECT * FROM users WHERE username = %s"
    param_1 = (username,)

    user = execute_read_query(connection, query_1, param_1)

    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, 
                                          detail="User not found")
    

    if delete and user:
        delete_query = "DELETE FROM users WHERE username = %s"
        delete_param = (user.get('username'),)
        result = execute_write_query(connection, delete_query, delete_param)

        if result == 1 :
            user = {'stat': 'Ok',
                    'Result': f"'user deleted Successfully!"}
            if token and isinstance(token, str):
                blacklist_token(username, token)
        else:
            raise HTTPException(status_code=status.HTTP_200_OK, 
                                          detail=f"Could not delete user:{username}")
        
    elif logout and user:
        if token and isinstance(token, str):
            blacklist_token(username, token)
            user = {'stat': 'Ok',
                    'Result': f"Logout success!"}
        else:
            raise HTTPException(status_code=status.HTTP_200_OK, 
                                          detail=f"Logout failed for:{username}")

    connection.close()
    return user

def validate_token(token: str = Depends(oauth2_scheme)):
    """Verify the JWT token and return the current user and role."""

    query = "SELECT * FROM token_blacklist WHERE token = %s"
    params = (token,)

    connection = create_connection()
    result = execute_read_query(connection, query, params)

    connection.close()

    #if the token is blacklisted(user logout or deleted user token)
    if result and token == result.get('token'):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid token. Please re-login")

    # verify the token
    payload = verify_access_token(token)

    if not payload:
        raise CREDENTIALS_EXCEPTION
    
    return payload.get('sub', ''), payload.get('role', '')
    

def get_current_user(user: str = Depends(validate_token)):

    username = user[0]

    user = manipulate_user(username)

    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, 
                                          detail="User not found")
    
    return user

def get_user_role(role:str = Depends(validate_token)):

    role_id = role[1] 

    if role_id == 1:
        role_name = 'admin'

    elif role_id == 2:
        role_name = 'user'
        
    else:
        role_name = ''
    
    return role_name


def role_required(required_role:str):
    
    def check_user_role(user_role : str  = Depends(get_user_role)):
        if required_role != user_role:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail = "You don't have permission to access this resource")
        
        return True

    return check_user_role

async def delete_user(username, request:Request):

    token = await oauth2_scheme(request)
    
    return manipulate_user(username, delete='Yes', token=token)


async def logout_user(username, request:Request):

    token = await oauth2_scheme(request)
    
    return manipulate_user(username, logout='Yes', token=token)
