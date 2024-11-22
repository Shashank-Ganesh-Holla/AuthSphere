import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock, AsyncMock, Mock, patch
from auth_app import app
from auth_app.services import UserService, get_user_service   
from auth_app.managers import RoleManager,UserRole, UserManager
from auth_app.utils import TokenFactory, TokenManager
from auth_app.repositories import UserRepository
from auth_app.schemas import User
from tests import BEARER_TOKEN, override_token_factory, override_get_user_service, override_get_current_user
from tests.routers import override_allowed_action
from fastapi import HTTPException, status
import os
from auth_app.core import config


@pytest.fixture
def override_dependencies(override_token_factory, override_get_user_service,
                          override_get_current_user, override_allowed_action):
    
    app.dependency_overrides[get_user_service] = lambda:override_get_user_service
    app.dependency_overrides[RoleManager.allowed_action] = override_allowed_action
    app.dependency_overrides[TokenFactory.validate_token] = lambda: override_token_factory
    app.dependency_overrides[UserManager.get_current_user] = lambda : override_get_current_user

    yield

    app.dependency_overrides = {}


@pytest.fixture
def client():
    return TestClient(app)


@pytest.mark.usefixtures("override_dependencies")
class TestAssignRole:

    def test_assign_role_success(self,client):

        """Test for assigning roles to users."""

        response = client.put('/user/assign-role/', 
        data={"username":"testuser", "role_name":"admin"},
        headers={"Authorization": f"Bearer {BEARER_TOKEN}"})

        assert response.status_code == 200

        data = response.json()

        assert data['stat'] == 'Ok'
        assert data['Result'] == "'admin' role_name for 'testuser' updated successfully! "


    def test_assign_role_user_not_found(self,client):

        """Test for assigning roles to users."""

        with patch('auth_app.services.UserService.assign_role',new=AsyncMock(side_effect= HTTPException(status.HTTP_404_NOT_FOUND, detail="User not found"))):
            
            response = client.put('/user/assign-role/',
            data={"username":"testuser", "role_name":"superuser"},
            headers={"Authorization": f"Bearer {BEARER_TOKEN}"})

        assert response.status_code == 404

        data = response.json()

        assert data['stat'] == 'Not_Ok'
        assert data['Reason'] == "User not found"


    def test_assign_role_expired_token(self,client):

        """Test for assigning roles to users."""

        expired_token = os.getenv('EXPIRED_TOKEN')
        assert expired_token is not None

        assert config.ACCESS_TOKEN_EXPIRE is not None

        del app.dependency_overrides[TokenFactory.validate_token] 

        
        with patch('auth_app.utils.TokenManager.is_token_blacklisted', new=AsyncMock(return_value={"token": BEARER_TOKEN})):    
            response = client.put('/user/assign-role/',
            data={"username":"testuser", "role_name":"admin"},
            headers={"Authorization": f"Bearer {BEARER_TOKEN}"})

        assert response.status_code == 401

        data = response.json()

        assert data['stat'] == 'Not_Ok'
        assert data['Reason'] == "User logged out. Please re-login"


    def test_assign_role_internal_server_error(self,client):

        """Test for assigning roles to users."""

        del app.dependency_overrides[RoleManager.allowed_action]
        del app.dependency_overrides[TokenFactory.validate_token] 
            
        response = client.put('/user/assign-role/',
        data={"username":"testuser", "role_name":"admin"},
        headers={"Authorization": f"Bearer {BEARER_TOKEN}"})

        assert response.status_code == 500

        data = response.json()

        assert data['stat'] == 'Not_Ok'
        assert data['Reason'] == "Internal Server Error"



@pytest.mark.usefixtures("override_dependencies")
class TestReadUsersMe:

    def test_read_users_me_success(self,client):

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



    def test_read_users_me_user_not_found(self,client):

        """Test for getting user details."""

        # Call the endpoint with a sample username

        del app.dependency_overrides[UserManager.get_current_user]

        with patch('auth_app.managers.UserManager.user_query', new=AsyncMock(return_value=None)):
            response = client.get('/user/read/users/', headers={"Authorization": f"Bearer {BEARER_TOKEN}"})


        # Assert that the status code is 404 Not_OK

        assert response.status_code == 404

        # Assert that the response JSON matches the expected structure

        data = response.json()

        assert data['stat'] == 'Not_Ok'
        assert data['Reason'] == 'User not found'




    def test_read_users_me_expired_token(self,client):

        """Test for getting user details."""

        # Call the endpoint with a sample username

        del app.dependency_overrides[TokenFactory.validate_token]
        del app.dependency_overrides[UserManager.get_current_user]


        with patch('auth_app.utils.TokenManager.is_token_blacklisted', new=AsyncMock(return_value={"token": BEARER_TOKEN})):
            response = client.get('/user/read/users/', headers={"Authorization": f"Bearer {BEARER_TOKEN}"})

        # Assert that the status code is 401 Not_OK

        assert response.status_code == 401

        # Assert that the response JSON matches the expected structure

        data = response.json()

        assert data['stat'] == 'Not_Ok'
        assert data['Reason'] == 'User logged out. Please re-login'



    def test_read_users_me_internal_server_error(self,client):

        """Test for getting user details."""

        # Call the endpoint with a sample username

        # del app.dependency_overrides[TokenFactory.validate_token]
        del app.dependency_overrides[UserManager.get_current_user]

       
        response = client.get('/user/read/users/', headers={"Authorization": f"Bearer {BEARER_TOKEN}"})

        # Assert that the status code is 500 Not_OK

        assert response.status_code == 500

        # Assert that the response JSON matches the expected structure

        data = response.json()

        assert data['stat'] == 'Not_Ok'
        assert data['Reason'] == 'Internal Server Error'



@pytest.mark.usefixtures("override_dependencies")
class TestGetUserDetails:

    def test_get_user_details_success(self,client):

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




    def test_get_user_details_no_token(self, client):

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



    def test_get_user_details_expired_token(self, client):

        """Test for getting user details."""

        # Call the endpoint with a sample username

        del app.dependency_overrides[TokenFactory.validate_token]
        del app.dependency_overrides[UserManager.get_current_user]


        with patch('auth_app.utils.TokenManager.is_token_blacklisted', new=AsyncMock(return_value={"token": BEARER_TOKEN})):
            response = client.get('/user/get-user-details/?username=testuser', headers={"Authorization": f"Bearer {BEARER_TOKEN}"})

        # Assert that the status code is 401 Not_OK

        assert response.status_code == 401

        # Assert that the response JSON matches the expected structure

        data = response.json()

        assert data['stat'] == 'Not_Ok'
        assert data['Reason'] == 'User logged out. Please re-login'



    def test_get_user_details_internal_server_error(self,client):

        """Test for getting user details."""

        # Call the endpoint with a sample username

        del app.dependency_overrides[TokenFactory.validate_token]
       
        response = client.get('/user/get-user-details/?username=testuser', headers={"Authorization": f"Bearer {BEARER_TOKEN}"})

        # Assert that the status code is 500 Not_OK

        assert response.status_code == 500

        # Assert that the response JSON matches the expected structure

        data = response.json()

        assert data['stat'] == 'Not_Ok'
        assert data['Reason'] == 'Internal Server Error'












