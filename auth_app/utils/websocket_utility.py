from fastapi import WebSocket, WebSocketDisconnect
from .token_helper import TokenFactory
from .exception_utility import WebSocketConnectionError, CUSTOM_CLOSE_CODES
from jose import JWTError, jwt
import logging
from auth_app.core import config, websocket_manager


async def utility_websocketAuth(websocket:WebSocket):

    await websocket_manager.connect(websocket)
    token = websocket.query_params.get('token')


    if not token:
        await websocket.send_text("No token provided, connection refuesd.")
        logging.warning("No token provided, connection refused.")
        raise WebSocketConnectionError("No token provided, connection refused.", code=CUSTOM_CLOSE_CODES.get('NO_TOKEN_RECEIVED'))
        

    try: 

        decoded_token = jwt.decode(token, config.SECRET_KEY, config.ALGORITHM)
        user = decoded_token.get('sub')
        await websocket.send_text(f"Authenticate user: {user}")
        await websocket.send_text(f"Upcoming messages above:")
       
    
    except JWTError as e:
        logging.warning(str(e))
        await websocket.send_text(f"{str(e)}, connection refuesd.")
        raise WebSocketConnectionError(f"{str(e)}, connection refuesd.",code=CUSTOM_CLOSE_CODES.get('TOKEN_ERROR'))
    
    except Exception as er:
        logging.error(str(er))
        await websocket.send_text(f"{str(er)}, connection refuesd.")
        raise er

    

    try:
        while True:

            data = await websocket.receive_text()

            await websocket.send_text(data)

    except WebSocketDisconnect:
        await websocket_manager.disconnect(websocket)

    except Exception as er:
        logging.error(str(er))
        await websocket.send_text(f"{str(er)}, connection refuesd.")
        raise er


