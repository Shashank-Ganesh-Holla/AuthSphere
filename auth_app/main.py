from fastapi import FastAPI, HTTPException, Request
import logging
# from core import setup_logging
from auth_app.core import setup_logging, config
from auth_app.routers import auth_router, resetPassword_router, user_router, test_router, ws_router, s3_router
from auth_app.utils import CustomExceptionHandler, TokenFactory, TokenBucket
from contextlib import asynccontextmanager
from fastapi.staticfiles import StaticFiles
import time
from collections import defaultdict

logging.getLogger("uvicorn").setLevel(logging.WARNING)

# In-memory bucket to store the token burst
bucket = defaultdict(lambda: TokenBucket(rate=2, capacity=5))

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
# app.include_router(router=ws_router, prefix="/ws", tags=["websocket"])
# app.include_router(router=s3_router, prefix="/s3", tags=["aws-s3"])


# add a rate limiting middleware
@app.middleware('http')
async def rate_limiter(request:Request, call_next):

    try:

        jwt_token = request.headers.get('Authorization')

        ip = request.client.host

        if jwt_token and jwt_token.startswith("Bearer "):

            bearer_token = jwt_token.split(" ")[1]
            try:
                id = TokenFactory.verify_token(bearer_token)
            except Exception:
                # fallback option, if the API is pre-login
                id = ip
        else:
            id = ip

        # add the id into the bucket dictionary, if it already present then no additional effect if not there then it creates
        # the key with the default values    
        token_bucket = bucket[id]

        # 'bucket' object which is an instance of TokenBucket class has a __call__ method so you can call the token_bucket()
        if not token_bucket():
            raise HTTPException(status_code=429, detail="Too many requests")
        
        response = await call_next(request)

        return response
    
    except Exception as err:
        if not isinstance(err, HTTPException):
            raise HTTPException(500, detail="Internal Server Error")
        raise


# Include exception handler
app.add_exception_handler(HTTPException, CustomExceptionHandler.http_exception_handler)

# Mount the static folder
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get('/')
def read_root(request:Request):
    return config.templates.TemplateResponse('home.html', {'request': request})



if __name__ == "__main__":
    import uvicorn

    # For Debugging purpose only(Running application using IDE debugger)

    uvicorn.run(app,log_level="info")

