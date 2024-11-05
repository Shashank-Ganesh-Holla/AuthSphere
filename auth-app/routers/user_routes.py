from fastapi import APIRouter, Depends, HTTPException, status, Request, Form
from auth import DatabaseManager, TokenFactory, UserManager, RoleManager, TokenManager
import logging
from typing import Union
from schemas import User, ClientResponse


router = APIRouter()


@router.get('/get-user-details/')
def get_user_details(username:str, 
                     current_user:None = Depends(TokenFactory.validate_token)):

    try:
        with DatabaseManager() as db:
            user_query = "SELECT * FROM users WHERE username = %s"
            user_param = (username,)

            is_user = db.execute_read(user_query, user_param)

        if not is_user:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="User not found")

        with DatabaseManager() as db:
            details_query = '''
            SELECT u.username, u.email, r.role_name 
            FROM users u
            INNER JOIN roles r
            ON u.role_id = r.role_id
            WHERE u.username = %s
            '''

            details_params = (username,)

            result = db.execute_read(details_query, details_params)

        if not result:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="User not found or role not assigned")
        
        return {'stat': 'Ok',
                'Result': result}
    
    except Exception as err:
        if not isinstance(err, HTTPException):
            logging.error(str(err))
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')
        else:
            raise


@router.get('/read/users', response_model=Union[User])
def read_users_me(user:User=Depends(UserManager.get_current_user)):

    try:
        return user
    
    except Exception as err:
        if not isinstance(err, HTTPException):
            logging.error(str(err))
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')
        else:
            raise


@router.put('/assign-role/', dependencies=[Depends(RoleManager.role_required('admin'))])
async def assign_role(request:Request, username:str = Form(...), 
                      role_name:str = Form(...)):

    try:        
        # first check if the user exists 
        with DatabaseManager() as db:
            query_user = "SELECT * FROM users WHERE username = %s"
            params_user = (username,)

            result = db.execute_read(query_user, params_user)

        # if user not found
        if not result:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="User not found")
        
        # Now check if the role_name in roles table and get the role_id
        with DatabaseManager() as db:
            query_role = "SELECT role_id FROM roles WHERE role_name = %s"
            params_role = (role_name,)
            role_id = db.execute_read(query_role, params_role)

        if not role_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="role_name not found")
        
        role_id = role_id.get('role_id')
        
        # now update the role id to the users table role_id column

        with DatabaseManager() as db:
            update_query_role = "UPDATE users SET role_id = %s WHERE username = %s"
            update_params_role = (role_id, username)
            update_result = db.execute_manipulation(update_query_role, update_params_role)


        if update_result == 1 :
            token = await TokenFactory.get_token_from_request(request)
            TokenManager.blacklist_token(username, token)

            return {"stat": "Ok",
                    "Result": f"'{role_name}' role_name for '{username}' updated successfully! "}
        
        else:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"'{role_name}' role already assigned!")
        
    except Exception as err:
        if not isinstance(err, HTTPException):
            logging.error(str(err))
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')
        else:
            raise


@router.post('/delete/user', response_model=Union[ClientResponse])
async def delete_user_me(request: Request, username:str = Form(...),
                   current_user:None = Depends(TokenFactory.validate_token)):    
    try:
        user = await UserManager.delete_user(username, request)
        return user
    
    except Exception as err:
        if not isinstance(err, HTTPException):
            logging.error(str(err))
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')
        else:
            raise