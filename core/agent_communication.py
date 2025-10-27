"""
Agent-to-Agent Communication System
Enables agents to communicate, coordinate, and share intelligence
"""

import asyncio
import json
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
import logging
from collections import defaultdict

log = logging.getLogger(__name__)


class Message:
    """Message between agents"""
    
    def __init__(
        self,
        from_agent: str,
        to_agent: str,
        message_type: str,
        payload: Dict[str, Any],
        priority: int = 5
    ):
        self.id = f"{datetime.utcnow().timestamp()}_{from_agent}_{to_agent}"
        self.from_agent = from_agent
        self.to_agent = to_agent
        self.message_type = message_type
        self.payload = payload
        self.priority = priority
        self.timestamp = datetime.utcnow()
        self.delivered = False
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'from': self.from_agent,
            'to': self.to_agent,
            'type': self.message_type,
            'payload': self.payload,
            'priority': self.priority,
            'timestamp': self.timestamp.isoformat(),
            'delivered': self.delivered
        }


class AgentCommunicator:
    """
    Agent Communication System
    
    Features:
    - Message passing between agents
    - Broadcast messages
    - Priority queues
    - Message subscriptions
    - Intelligence sharing
    """
    
    def __init__(self):
        # Agent registry
        self.agents: Dict[str, Any] = {}
        
        # Message queues per agent
        self.message_queues: Dict[str, asyncio.Queue] = defaultdict(asyncio.Queue)
        
        # Subscriptions (agent -> message types)
        self.subscriptions: Dict[str, List[str]] = defaultdict(list)
        
        # Message handlers (agent -> type -> handler)
        self.handlers: Dict[str, Dict[str, Callable]] = defaultdict(dict)
        
        # Shared intelligence database
        self.intelligence_db: Dict[str, Any] = {}
        
        # Statistics
        self.stats = {
            'messages_sent': 0,
            'messages_delivered': 0,
            'broadcasts': 0,
            'intelligence_shared': 0
        }
    
    async def register_agent(
        self,
        agent_name: str,
        agent_instance: Any,
        capabilities: List[str] = None
    ):
        """
        Register an agent in the communication system
        
        Args:
            agent_name: Unique agent identifier
            agent_instance: Agent instance
            capabilities: List of agent capabilities
        """
        log.info(f"[AgentComm] Registering agent: {agent_name}")
        
        self.agents[agent_name] = {
            'instance': agent_instance,
            'capabilities': capabilities or [],
            'registered_at': datetime.utcnow(),
            'messages_sent': 0,
            'messages_received': 0
        }
        
        # Create message queue
        if agent_name not in self.message_queues:
            self.message_queues[agent_name] = asyncio.Queue()
        
        log.info(f"[AgentComm] Agent {agent_name} registered with {len(capabilities or [])} capabilities")
    
    async def unregister_agent(self, agent_name: str):
        """Unregister an agent"""
        if agent_name in self.agents:
            del self.agents[agent_name]
            log.info(f"[AgentComm] Agent {agent_name} unregistered")
    
    async def send_message(
        self,
        from_agent: str,
        to_agent: str,
        message_type: str,
        payload: Dict[str, Any],
        priority: int = 5
    ) -> bool:
        """
        Send message from one agent to another
        
        Args:
            from_agent: Sender agent name
            to_agent: Recipient agent name
            message_type: Type of message
            payload: Message payload
            priority: Message priority (1-10, higher = more important)
        
        Returns:
            True if message was queued successfully
        """
        if to_agent not in self.agents:
            log.warning(f"[AgentComm] Target agent {to_agent} not registered")
            return False
        
        message = Message(from_agent, to_agent, message_type, payload, priority)
        
        await self.message_queues[to_agent].put(message)
        
        self.stats['messages_sent'] += 1
        if from_agent in self.agents:
            self.agents[from_agent]['messages_sent'] += 1
        
        log.debug(f"[AgentComm] Message sent: {from_agent} -> {to_agent} ({message_type})")
        
        return True
    
    async def receive_message(
        self,
        agent_name: str,
        timeout: Optional[float] = None
    ) -> Optional[Message]:
        """
        Receive next message for an agent
        
        Args:
            agent_name: Agent name
            timeout: Timeout in seconds (None = wait forever)
        
        Returns:
            Message or None if timeout
        """
        if agent_name not in self.agents:
            return None
        
        try:
            if timeout:
                message = await asyncio.wait_for(
                    self.message_queues[agent_name].get(),
                    timeout=timeout
                )
            else:
                message = await self.message_queues[agent_name].get()
            
            message.delivered = True
            self.stats['messages_delivered'] += 1
            self.agents[agent_name]['messages_received'] += 1
            
            log.debug(f"[AgentComm] Message received by {agent_name}: {message.message_type}")
            
            return message
            
        except asyncio.TimeoutError:
            return None
    
    async def broadcast(
        self,
        from_agent: str,
        message_type: str,
        payload: Dict[str, Any],
        exclude: List[str] = None
    ):
        """
        Broadcast message to all agents
        
        Args:
            from_agent: Sender agent name
            message_type: Type of message
            payload: Message payload
            exclude: List of agents to exclude
        """
        exclude = exclude or []
        
        recipients = [
            agent_name for agent_name in self.agents.keys()
            if agent_name not in exclude and agent_name != from_agent
        ]
        
        for recipient in recipients:
            await self.send_message(from_agent, recipient, message_type, payload)
        
        self.stats['broadcasts'] += 1
        
        log.info(f"[AgentComm] Broadcast from {from_agent} to {len(recipients)} agents")
    
    async def subscribe(
        self,
        agent_name: str,
        message_types: List[str]
    ):
        """
        Subscribe agent to specific message types
        
        Args:
            agent_name: Agent name
            message_types: List of message types to subscribe to
        """
        self.subscriptions[agent_name].extend(message_types)
        log.info(f"[AgentComm] {agent_name} subscribed to {len(message_types)} message types")
    
    async def register_handler(
        self,
        agent_name: str,
        message_type: str,
        handler: Callable
    ):
        """
        Register message handler for specific message type
        
        Args:
            agent_name: Agent name
            message_type: Message type
            handler: Async function to handle message
        """
        self.handlers[agent_name][message_type] = handler
        log.info(f"[AgentComm] Handler registered: {agent_name}.{message_type}")
    
    async def share_intelligence(
        self,
        agent_name: str,
        intel_type: str,
        data: Any
    ):
        """
        Share intelligence with all agents
        
        Args:
            agent_name: Agent sharing intelligence
            intel_type: Type of intelligence
            data: Intelligence data
        """
        intel_id = f"{intel_type}_{datetime.utcnow().timestamp()}"
        
        self.intelligence_db[intel_id] = {
            'type': intel_type,
            'data': data,
            'shared_by': agent_name,
            'timestamp': datetime.utcnow()
        }
        
        # Broadcast intelligence to all agents
        await self.broadcast(
            agent_name,
            'intelligence_update',
            {
                'intel_id': intel_id,
                'intel_type': intel_type,
                'data': data
            }
        )
        
        self.stats['intelligence_shared'] += 1
        
        log.info(f"[AgentComm] Intelligence shared: {intel_type} by {agent_name}")
    
    async def get_intelligence(
        self,
        intel_type: Optional[str] = None
    ) -> List[Dict]:
        """
        Get intelligence from database
        
        Args:
            intel_type: Filter by intelligence type (None = all)
        
        Returns:
            List of intelligence entries
        """
        if intel_type:
            return [
                intel for intel in self.intelligence_db.values()
                if intel['type'] == intel_type
            ]
        else:
            return list(self.intelligence_db.values())
    
    async def request_assistance(
        self,
        agent_name: str,
        capability_needed: str,
        context: Dict[str, Any]
    ) -> Optional[str]:
        """
        Request assistance from agents with specific capability
        
        Args:
            agent_name: Agent requesting assistance
            capability_needed: Required capability
            context: Request context
        
        Returns:
            Name of agent that can assist, or None
        """
        # Find agents with required capability
        capable_agents = [
            name for name, info in self.agents.items()
            if capability_needed in info.get('capabilities', [])
            and name != agent_name
        ]
        
        if not capable_agents:
            log.warning(f"[AgentComm] No agent found with capability: {capability_needed}")
            return None
        
        # Send request to first capable agent
        assistant = capable_agents[0]
        
        await self.send_message(
            agent_name,
            assistant,
            'assistance_request',
            {
                'capability': capability_needed,
                'context': context
            },
            priority=8
        )
        
        log.info(f"[AgentComm] Assistance requested: {agent_name} -> {assistant}")
        
        return assistant
    
    async def coordinate_attack(
        self,
        coordinator: str,
        agents: List[str],
        attack_plan: Dict[str, Any]
    ):
        """
        Coordinate multi-agent attack
        
        Args:
            coordinator: Coordinating agent
            agents: List of agents to coordinate
            attack_plan: Attack plan with tasks for each agent
        """
        log.info(f"[AgentComm] Coordinating attack with {len(agents)} agents")
        
        # Send attack plan to each agent
        for agent_name in agents:
            if agent_name in self.agents:
                await self.send_message(
                    coordinator,
                    agent_name,
                    'attack_coordination',
                    {
                        'plan': attack_plan,
                        'role': attack_plan.get('roles', {}).get(agent_name, 'support')
                    },
                    priority=9
                )
    
    def get_stats(self) -> Dict:
        """Get communication statistics"""
        return {
            **self.stats,
            'registered_agents': len(self.agents),
            'pending_messages': sum(
                q.qsize() for q in self.message_queues.values()
            ),
            'intelligence_entries': len(self.intelligence_db)
        }
    
    async def start_message_processor(self, agent_name: str):
        """
        Start processing messages for an agent
        
        Args:
            agent_name: Agent name
        """
        log.info(f"[AgentComm] Starting message processor for {agent_name}")
        
        while agent_name in self.agents:
            try:
                # Receive message with timeout
                message = await self.receive_message(agent_name, timeout=1.0)
                
                if message:
                    # Check if handler is registered
                    if message.message_type in self.handlers.get(agent_name, {}):
                        handler = self.handlers[agent_name][message.message_type]
                        await handler(message)
                    else:
                        log.debug(f"[AgentComm] No handler for {message.message_type} in {agent_name}")
                
            except Exception as e:
                log.error(f"[AgentComm] Error processing message for {agent_name}: {e}")
                await asyncio.sleep(0.1)


# Global communicator instance
_communicator = None


def get_communicator() -> AgentCommunicator:
    """Get global communicator instance"""
    global _communicator
    if _communicator is None:
        _communicator = AgentCommunicator()
    return _communicator

