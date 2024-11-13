from fastapi import FastAPI, HTTPException
import logging
from core import setup_logging
from routers import auth_router, user_router, test_router, ws_router, s3_router
from utils import CustomExceptionHandler

logging.getLogger("uvicorn").setLevel(logging.WARNING)

app = FastAPI()

# Include routers with different prefixes
app.include_router(router=auth_router, prefix='/auth', tags=["auth"])
app.include_router(router=user_router, prefix='/user', tags=["user"])
app.include_router(router=test_router, prefix='/test', tags=["test"])
app.include_router(router=ws_router, prefix="/ws", tags=["websocket"])
app.include_router(router=s3_router, prefix="/s3", tags=["aws-s3"])



# Include exception handler
app.add_exception_handler(HTTPException, CustomExceptionHandler.http_exception_handler)



@app.on_event("startup")
async def startup_event():
    # Perform startup actions
    setup_logging()
    logging.info("AuthSphere started successfully!")
    pass



@app.get('/')
def read_root():
    return {"message":"Welcome to the Authentication App"}



if __name__ == "__main__":
    import uvicorn

    # For Debugging purpose only(Running application using IDE debugger)

    uvicorn.run(app,log_level="info")

