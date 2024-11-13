from fastapi import WebSocket


CUSTOM_CLOSE_CODES = {
    "TOKEN_EXPIRED": 4001,
    "INVALID_TOKEN": 4002,
    "CONNECTION_REFUSED": 4003,
    "NO_TOKEN_RECEIVED" : 4004,
    "TOKEN_ERROR"       : 4005,
    "ANY_EXCEPTION"       : 4006,
    # Add more as needed
}




class WebSocketConnectionError(Exception):
    def __init__(self, detail, code=1000) -> None:
        super().__init__(detail)

        self.detail = detail
        self.code = code
