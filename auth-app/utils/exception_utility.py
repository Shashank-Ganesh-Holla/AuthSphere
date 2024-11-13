from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from typing import Union


CUSTOM_CLOSE_CODES = {
    "TOKEN_EXPIRED": 4001,
    "INVALID_TOKEN": 4002,
    "CONNECTION_REFUSED": 4003,
    "NO_TOKEN_RECEIVED" : 4004,
    "TOKEN_ERROR"       : 4005,
    "ANY_EXCEPTION"       : 4006,
    # Add more as needed
}


class CustomExceptionHandler:

    @staticmethod
    async def http_exception_handler(request: Request, exc: Union[Exception, HTTPException]):
        """
        Custom exception handler that catches HTTPException.
        It returns a structured JSON response for the client.
        """

        return JSONResponse(
            status_code=exc.status_code,
            content={"stat": "Not_Ok", "Reason": exc.detail},
        )




class WebSocketConnectionError(Exception):
    def __init__(self, detail, code=1000) -> None:
        super().__init__(detail)

        self.detail = detail
        self.code = code
