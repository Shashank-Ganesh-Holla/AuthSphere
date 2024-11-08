from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
import logging
from core import Logger
from routers import auth_router, user_router, test_router
from typing import Union

logging.getLogger("uvicorn").setLevel(logging.WARNING)

app = FastAPI()

# Include routers with different prefixes
app.include_router(router=auth_router, prefix='/auth', tags=["auth"])
app.include_router(router=user_router, prefix='/user', tags=["user"])
app.include_router(router=test_router, prefix='/test', tags=["test"])



@app.on_event("startup")
async def startup_event():
    # Perform startup actions
    Logger.setup_logging()
    logging.info("AuthSphere started successfully!")
    pass


@app.exception_handler(HTTPException)  # Catch any exception
async def general_exception_handler(request: Request, exc: Union[Exception, HTTPException]):
    """
    Custom exception handler that catches HTTPException.
    It returns a structured JSON response for the client and logs the error.
    """
    # if isinstance(exc, HTTPException):
    #     # If it's an HTTPException, we handle it as usual
    return JSONResponse(
        status_code=exc.status_code,
        content={"stat": "Not_Ok", "Reason": exc.detail},
    )

@app.get('/')
def read_root():
    return {"message":"Welcome to the Authentication App"}



if __name__ == "__main__":
    import uvicorn

    # For Debugging purpose only(Running application using IDE debugger)

    uvicorn.run(app,log_level="info")

