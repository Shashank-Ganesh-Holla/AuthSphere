from fastapi import FastAPI, HTTPException
import logging
# from core import setup_logging
from auth_app.core import setup_logging
from auth_app.routers import auth_router, resetPassword_router, user_router, test_router, ws_router, s3_router
from auth_app.utils import CustomExceptionHandler
from contextlib import asynccontextmanager

logging.getLogger("uvicorn").setLevel(logging.WARNING)


# this is an alternative method for "on_event" as on_event method have been deprecated
@asynccontextmanager
async def lifespan(app: FastAPI):

    """
    This is an alternative method for handling the lifecycle events (startup and shutdown) of the FastAPI app. 
    The 'on_event' method has been deprecated, so the 'lifespan' context manager, decorated with @asynccontextmanager, 
    is used to implement the startup and shutdown logic for the FastAPI app.

    Once the startup logic is complete, control is yielded to FastAPI, allowing it to start handling incoming requests.

    """
    # Perform startup actions
    setup_logging()
    logging.info("AuthSphere started successfully!")

    yield

    # Perform shutdown actions
    logging.info("AuthSphere shutting down...")

# Setup FastAPI app with the lifespan context manager
app = FastAPI(title="AuthSphere", lifespan=lifespan)

# Include routers with different prefixes
app.include_router(router=auth_router, prefix='/auth', tags=["auth"])
app.include_router(router=resetPassword_router, prefix='/reset', tags=["reset"])
app.include_router(router=user_router, prefix='/user', tags=["user"])
app.include_router(router=test_router, prefix='/test', tags=["test"])
app.include_router(router=ws_router, prefix="/ws", tags=["websocket"])
app.include_router(router=s3_router, prefix="/s3", tags=["aws-s3"])



# Include exception handler
app.add_exception_handler(HTTPException, CustomExceptionHandler.http_exception_handler)



@app.get('/')
def read_root():
    return {"message":"Welcome to the AuthSphere App"}



if __name__ == "__main__":
    import uvicorn

    # For Debugging purpose only(Running application using IDE debugger)

    uvicorn.run(app,log_level="info")

