from fastapi import APIRouter, Depends, HTTPException, status, Request, Form
from managers import UserManager, RoleManager
import logging
from typing import Union
from schemas import User, ClientResponse
from utils import TokenManager, TokenFactory, DatabaseManager
from services import get_user_service, UserService


router = APIRouter()


@router.get('/get-user-details/')
async def get_user_details(username:str, 
                     current_user:None = Depends(TokenFactory.validate_token),
                     user_service : UserService = Depends(get_user_service)):
    
    try:
        result = await user_service.get_user_details(username=username)
        return result
    
    except Exception as err:
        if not isinstance(err, HTTPException):
            logging.error(str(err))
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')
        else:
            raise


@router.get('/read/users', response_model=Union[User])
async def read_users_me(user:User=Depends(UserManager.get_current_user)):

    try:
        return user
    
    except Exception as err:
        if not isinstance(err, HTTPException):
            logging.error(str(err))
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')
        else:
            raise

# 
@router.put('/assign-role/', dependencies=[Depends(RoleManager.role_required('admin'))])
async def assign_role(request:Request, username:str = Form(...), 
                      role_name:str = Form(...), user_service : UserService = Depends(get_user_service)):

    try:

        await user_service.assign_role(username=username, role_name=role_name)

        return {"stat": "Ok",
                "Result": f"'{role_name}' role_name for '{username}' updated successfully! "}

        
    except Exception as err:
        if not isinstance(err, HTTPException):
            logging.error(str(err))
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')
        else:
            raise


@router.post('/delete/user', response_model=Union[ClientResponse])
async def delete_user_me(request: Request, username:str = Form(...),
                   current_user:str = Depends(TokenFactory.validate_token),
                   user_service : UserService = Depends(get_user_service)):    
    try:
        if current_user[0] != username and current_user[1] == 2:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You dont have privilige to delete other users")

        user = await user_service.delete_user_me(request=request, username=username)
        return user
    
    except Exception as err:
        if not isinstance(err, HTTPException):
            logging.error(str(err))
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')
        else:
            raise