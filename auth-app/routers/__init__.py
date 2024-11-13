from .auth_routes import router as auth_router
from .user_routes import router as user_router
from .test_routes import router as test_router
from .ws_routes import router   as ws_router
from .s3_routes import router as s3_router

__all__ = ["auth_router", "user_router", "test_router", "ws_router", "s3_router"]
