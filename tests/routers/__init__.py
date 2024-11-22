import pytest


@pytest.fixture
def override_allowed_action():
    return lambda action: True


    
      
__all__ = ["override_allowed_action"]