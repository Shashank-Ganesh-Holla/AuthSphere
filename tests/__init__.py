import pytest
from auth_app.services import UserService
import os
import logging


@pytest.fixture
def override_token_factory():
    return ("testuser", 1)




# some dummy expired bearer
BEARER_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0dXNlciIsInJvbGUiOjIsImV4cCI6MTczMjAxODY2MSwidHlwZSI6ImFjY2VzcyJ9.npfx4CYhZOF618i21pNDdqIIM68AC0ezs6KYkhw8nQ4'
# BEARER_TOKEN = os.getenv("EXPIRED_TOKEN")

@pytest.fixture
def override_get_current_user():

    return {
        "id": "1141",
        "username": "testuser",
        "email" : "test@gmail.com",
        "password" : "sadfasdfdsfdasfsdfadf",
        "role_id"  : 2,
        "twofa_status": 0
    }



class MockUserRepository:
    async def get_user_details(self, username: str):
        user_details = {
                    "stat": "Ok",
                    "Result": {
                                "username": "testuser",
                                "email": "test@gmail.com",
                                "role_name": "admin"
                                }
                    }
        
        return user_details
    

    async def assign_role(self, username, role_name):
        return True
    


@pytest.fixture    
def override_get_user_service():
   mock_user_repo = MockUserRepository()

   return UserService(user_repo=mock_user_repo)





__all__ = ["override_get_user_service", "MockUserRepository", "override_get_current_user", "override_token_factory",
           "BEARER_TOKEN"]