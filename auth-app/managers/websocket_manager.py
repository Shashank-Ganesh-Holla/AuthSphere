from fastapi import WebSocket
from typing import List
import logging


class WebsocketManager:

    def __init__(self):
        
        self.connections : List[WebSocket] = [] # Connection pool
        self.message_queue = []  # message queue

    async def connect(self, websocket:WebSocket):

        await websocket.accept()
        self.connections.append(websocket)

        await websocket.send_text("Queued messages(Last 10)")

        for message in self.message_queue[-10:]:
            await websocket.send_text(message)

    async def broadcast(self, message):

        self.message_queue.append(message)

        if len(self.message_queue) > 100:
            self.message_queue.pop(0)

        for connection in self.connections:
            try:
                await connection.send_text(message)
            except RuntimeError as e:
                logging.warning(f"Removing closed connection due to error: {e}")
                await self.disconnect(connection)  # Close and remove from pool

    
    async def disconnect(self, websocket:WebSocket):
        await websocket.close()
        self.connections.remove(websocket)
        



