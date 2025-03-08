from fastapi import HTTPException, status, Depends
import logging
from auth_app.utils import TokenFactory, can_execute_action
from auth_app.managers import UserRole
import asyncio

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

            elif role_id == 3:
                role_name = 'guest'
                
            else:
                role_name = ''
            
            return UserRole(role_name=role_name, user=role[0])
            # return role_name, role[0]
        
        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured : {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")   
            else:
                raise 


    @staticmethod
    def allowed_action(required_action:str, **kwargs):

        """
        Checks if the user with a specific role is allowed to perform the given action.

        This function performs a validation to ensure that the user's role permits the 
        specified action. If the action is restricted, an HTTP 403 Forbidden exception 
        is raised. Additionally, for actions like "delete_user_me," further validation 
        ensures that users cannot delete other users unless they have admin privileges.

        Args:
            required_action (str): The action to check (e.g., "delete_user_me", "assign_role").
            user_role (UserRole): An object representing the user's role and identity, 
                                  provided via dependency injection. Defaults to the result 
                                  of the `get_user_role` function.
            **kwargs: Additional parameters required for specific actions, such as `username` in case of "delete_user_me" action.

        Returns:
            bool: True if the user is allowed to perform the action.

        Raises:
            HTTPException: 
                - 403 Forbidden: If the user's role does not have permission for the required action
                  or if the user attempts to perform an unauthorized operation, such as deleting 
                  another user's account without admin privileges.
                - 500 Internal Server Error: If an unexpected error occurs during the check.

        Special Behavior:
            - For `delete_user_me`, additional checks ensure:
                1. Non-admin users can only delete their own accounts.
                2. If the `username` in the request differs from the token's user and the role is not
                   "admin," the action is forbidden.

        Notes:
            - The `can_execute_action` function is used to validate role-to-action permissions.
            - Unexpected exceptions are logged before raising an HTTP 500 error.

        """

        try:

            async def check_user_role(user_role : UserRole  = Depends(RoleManager.get_user_role)):

                role = user_role.role_name

                if not role == 'admin':

                    is_allowed_action = can_execute_action(user_role=role, required_action=required_action)

                    if not is_allowed_action:
                        raise HTTPException(status.HTTP_403_FORBIDDEN, detail = "You don't have permission to access this resource")
                
                # if the required_action is delete_user_me then we will return the user_role so that we can verify in the route method 
                # if the user_role is not admin and if the input username != user in the token then forbid deleting other users

                    if required_action == 'delete_user_me' :
                        return user_role

                
                if required_action == 'delete_user_me' :
                    return user_role
                
                return True
            
            return check_user_role

    
        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured : {str(er)}")
                raise  HTTPException(500, detail="Internal Server Error")   
            else:
                raise 



    @staticmethod
    def backup_role_required(required_role:str):

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


