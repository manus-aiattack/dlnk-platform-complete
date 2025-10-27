import json
import time
import websockets
from core.logger import log
from core.pubsub_manager import PubSubManager

class EventDispatcher:
    def __init__(self, websocket=None):
        self.pubsub_manager = PubSubManager()
        self.websocket = websocket

    async def setup(self):
        """Initializes the dispatcher components."""
        await self.pubsub_manager.setup()

    async def dispatch_dashboard_update(self, data: dict):
        """Sends a data payload to the dashboard server via websocket."""
        if self.websocket:
            try:
                await self.websocket.send(json.dumps(data))
            except websockets.exceptions.ConnectionClosed:
                log.warning("Dashboard websocket connection closed. Dashboard will not be updated.")
                self.websocket = None
            except Exception as e:
                log.error(f"Error sending dashboard update: {e}")
                self.websocket = None # Assume connection is bad
        else:
            log.debug("Dashboard websocket not connected. Skipping update.")

    async def dispatch_agent_completed_event(self, agent_name: str, cycle_id: str, success: bool, error_type: str = None, summary: str = ""):
        """Publishes an AGENT_COMPLETED event to the pub/sub system."""
        event_data = {
            "event_type": "AGENT_COMPLETED",
            "agent_name": agent_name,
            "cycle_id": cycle_id,
            "success": success,
            "error_type": error_type,
            "summary": summary,
            "timestamp": time.time()
        }
        await self.pubsub_manager.publish("agent_events", event_data)

    async def close(self):
        """Closes the connections for the dispatcher components."""
        if self.pubsub_manager:
            await self.pubsub_manager.close()
        if self.websocket:
            await self.websocket.close()
