from fastapi import APIRouter, WebSocket, HTTPException, status, WebSocketDisconnect
from auth_app.utils import utility_websocketAuth, WebSocketConnectionError
from starlette.websockets import WebSocketState
import logging


router = APIRouter()



@router.websocket('/auth')
async def webSocketServer_auth(websocket:WebSocket):

    try:
        await utility_websocketAuth(websocket)

    except WebSocketDisconnect:
        pass

    except WebSocketConnectionError as e:
        await websocket.close(e.code)

    except Exception as e:
        
        if websocket.client_state != WebSocketState.CONNECTED:
            await websocket.close(code=1011)
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail = "Internal Server Error")
        
        elif not isinstance(e, WebSocketConnectionError):
            await websocket.close(code=1011)
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail = "Internal Server Error")

        raise


