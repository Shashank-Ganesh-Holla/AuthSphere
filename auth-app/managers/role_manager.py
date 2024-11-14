from fastapi import HTTPException, status, Depends
import logging
from utils import TokenFactory


# ! Factory pattern implemented !
class RoleManager:

    """Manages user roles and access permissions."""

    @staticmethod
    async def get_user_role(role:str = Depends(TokenFactory.validate_token)):

        try:

            """Determines the role of the current user based on the token."""

            role_id = role[1] 

            if role_id == 1:
                role_name = 'admin'

            elif role_id == 2:
                role_name = 'user'
                
            else:
                role_name = ''
            
            return role_name
        
        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured : {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")   
            else:
                raise 

    @staticmethod
    def role_required(required_role:str):

        try:

            """Defines a role requirement check for specific resources."""
            
            '''A closure function used here that helps in calling an inner function and accessing the params of outer function
            even after the outer function is completely executed. FastAPI will execute the returned check_user_role function 
            even though () is not suffixed to it.'''

            async def check_user_role(user_role : str  = Depends(RoleManager.get_user_role)):
                if required_role != user_role:
                    raise HTTPException(status.HTTP_403_FORBIDDEN, detail = "You don't have permission to access this resource")
                
                return True

            return check_user_role
    
        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured : {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")   
            else:
                raise 


