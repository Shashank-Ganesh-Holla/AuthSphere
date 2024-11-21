from fastapi import APIRouter, Depends, HTTPException, status, Request, Form
from auth_app.managers import UserManager, RoleManager, UserRole
import logging
from typing import Union
from auth_app.schemas import User, ClientResponse
from auth_app.utils import TokenManager, TokenFactory, DatabaseManager
from auth_app.services import get_user_service, UserService


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


@router.get('/read/users', response_model=User)
async def read_users_me(user=Depends(UserManager.get_current_user)):

    try:
        return user
    
    except Exception as err:
        if not isinstance(err, HTTPException):
            logging.error(str(err))
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')
        else:
            raise

# 
@router.put('/assign-role/')
async def assign_role(request:Request, username:str = Form(...), 
                      role_name:str = Form(...), user_service : UserService = Depends(get_user_service),
                      has_permission : None = Depends(RoleManager.allowed_action('assign_role'))):

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
                   user_service : UserService = Depends(get_user_service),
                   check_user : UserRole = Depends(RoleManager.allowed_action('delete_user_me'))):    
    try:

        if username != check_user.user and check_user.role_name != 'admin':
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail = "You dont have privilige to delete other users")

        user = await user_service.delete_user_me(request=request, username=username)
        return user
    
    except Exception as err:
        if not isinstance(err, HTTPException):
            logging.error(str(err))
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')
        else:
            raise