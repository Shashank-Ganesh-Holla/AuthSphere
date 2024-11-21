import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock, AsyncMock, Mock
from auth_app import app
from auth_app.services import UserService, get_user_service   
from auth_app.managers import RoleManager,UserRole, UserManager
from auth_app.utils import TokenFactory
from auth_app.repositories import UserRepository
from auth_app.schemas import User


@pytest.fixture
def override_token_factory():
    return {"username": "testuser", "role": "admin"}


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
def override_allowed_action():
    return lambda action: True  
    

@pytest.fixture    
def override_get_user_service():
   mock_user_repo = MockUserRepository()

   return UserService(user_repo=mock_user_repo)


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



@pytest.fixture
def override_dependencies(override_token_factory, override_get_user_service,
                          override_get_current_user, override_allowed_action):
    
    app.dependency_overrides[get_user_service] = lambda:override_get_user_service
    # app.dependency_overrides[RoleManager.allowed_action] = override_allowed_action
    app.dependency_overrides[TokenFactory.validate_token] = lambda: override_token_factory
    app.dependency_overrides[UserManager.get_current_user] = lambda : override_get_current_user

    yield

    app.dependency_overrides = {}


@pytest.fixture
def client():
    return TestClient(app)










def test_read_users_me(client, override_dependencies):

    """Test for getting user details."""

    # Call the endpoint with a sample username

    response = client.get('/user/read/users/')

    # Assert that the status code is 200 OK

    # assert response.json() == {}
    assert response.status_code == 200

    # Assert that the response JSON matches the expected structure

    data = response.json()

    assert data['username'] == 'testuser'
    assert data['email'] == 'test@gmail.com'



def test_read_users_me_expired_token(client, override_dependencies):

    """Test for getting user details."""

    # Call the endpoint with a sample username

    del app.dependency_overrides[TokenFactory.validate_token]
    del app.dependency_overrides[UserManager.get_current_user]

    # some dummy expired bearer
    bearer = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0dXNlciIsInJvbGUiOjIsImV4cCI6MTczMjAxODY2MSwidHlwZSI6ImFjY2VzcyJ9.npfx4CYhZOF618i21pNDdqIIM68AC0ezs6KYkhw8nQ4'

    response = client.get('/user/read/users/', headers={"Authorization": f"Bearer {bearer}"})

    # Assert that the status code is 401 Not_OK

    assert response.status_code == 401

    # Assert that the response JSON matches the expected structure

    data = response.json()

    assert data['stat'] == 'Not_Ok'
    assert data['Reason'] == 'User logged out. Please re-login'



def test_get_user_details(client, override_dependencies):

    """Test for getting user details."""

    # Call the endpoint with a sample username

    response = client.get('/user/get-user-details/?username=testuser')

    # Assert that the status code is 200 OK

    assert response.status_code == 200

    # Assert that the response JSON matches the expected structure

    data = response.json()

    assert data['stat'] == 'Ok'
    assert data['Result']['username'] == 'testuser'
    assert data['Result']['email'] == 'test@gmail.com'
    assert data['Result']['role_name'] == 'admin'




def test_get_user_details_no_token(client, override_dependencies):

    """Test for getting user details."""

    # Call the endpoint with a sample username

    del app.dependency_overrides[TokenFactory.validate_token]

    response = client.get('/user/get-user-details/?username=testuser')

    # Assert that the status code is 401 Not_OK

    assert response.status_code == 401

    # Assert that the response JSON matches the expected structure

    data = response.json()

    assert data['stat'] == 'Not_Ok'
    assert data['Reason'] == 'Not authenticated'




def test_get_user_details_expired_token(client, override_dependencies):

    """Test for getting user details."""

    # Call the endpoint with a sample username

    del app.dependency_overrides[TokenFactory.validate_token]

    # some dummy expired bearer
    bearer = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0dXNlciIsInJvbGUiOjIsImV4cCI6MTczMjAxODY2MSwidHlwZSI6ImFjY2VzcyJ9.npfx4CYhZOF618i21pNDdqIIM68AC0ezs6KYkhw8nQ4'

    response = client.get('/user/get-user-details/?username=testuser', headers={"Authorization": f"Bearer {bearer}"})

    # Assert that the status code is 401 Not_OK

    assert response.status_code == 401

    # Assert that the response JSON matches the expected structure

    data = response.json()

    assert data['stat'] == 'Not_Ok'
    assert data['Reason'] == 'User logged out. Please re-login'












