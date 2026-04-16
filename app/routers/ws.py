from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.services.ws_manager import ws_manager

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/events")
async def websocket_events(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        while True:
            # Keep connection alive; server pushes events via ws_manager.broadcast()
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
