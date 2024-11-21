from typing import List
from .action_and_roles import action_and_roles



def can_execute_action(user_role:str, required_action:str):

    """
    Checks if a user with a given role can perform a specific action.

    Args:
        user_role (str): The role of the user (e.g., "admin", "user").
        required_action (str): The action to check (e.g., "assign_role", "delete_user_me").

    Returns:
        bool: True if the user is allowed to perform the action, False otherwise.
    """

    user_allowed_actions : List[str] = action_and_roles.get(user_role, [])

    return required_action in user_allowed_actions




# print(can_execute_action('user', 'assign_role'))