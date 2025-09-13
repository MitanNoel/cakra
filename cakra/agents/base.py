"""CAKRA - Base Agent Interface

Defines the base interface for all CAKRA analysis agents.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import asyncio
from datetime import datetime

class Agent(ABC):
    """Base agent interface that all CAKRA agents must implement"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.is_initialized = False
    
    @abstractmethod
    async def initialize(self) -> None:
        """Initialize agent resources and connections"""
        pass
    
    @abstractmethod
    async def analyze(self, data: Any) -> Dict[str, Any]:
        """Perform agent-specific analysis"""
        pass
    
    @abstractmethod
    async def cleanup(self) -> None:
        """Clean up agent resources"""
        pass
    
    async def __aenter__(self):
        """Context manager entry"""
        if not self.is_initialized:
            await self.initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        await self.cleanup()
        self.is_initialized = False

class BatchAgent(Agent):
    """Base class for agents that support batch processing"""
    
    def __init__(self, config: Dict[str, Any], batch_size: int = 10):
        super().__init__(config)
        self.batch_size = batch_size
        self._batch_queue: List[Any] = []
        self._results: Dict[str, Any] = {}
    
    @abstractmethod
    async def process_batch(self, batch: List[Any]) -> List[Dict[str, Any]]:
        """Process a batch of items"""
        pass
    
    async def add_to_batch(self, item: Any, item_id: str) -> None:
        """Add an item to the processing queue"""
        self._batch_queue.append((item_id, item))
        
        if len(self._batch_queue) >= self.batch_size:
            await self._process_current_batch()
    
    async def _process_current_batch(self) -> None:
        """Process current items in the batch queue"""
        if not self._batch_queue:
            return
            
        batch_items = [(id_, item) for id_, item in self._batch_queue]
        self._batch_queue.clear()
        
        try:
            results = await self.process_batch([item for _, item in batch_items])
            for (id_, _), result in zip(batch_items, results):
                self._results[id_] = result
        except Exception as e:
            # Add error result for all items in failed batch
            error_result = {"error": str(e), "timestamp": datetime.utcnow()}
            for id_, _ in batch_items:
                self._results[id_] = error_result
    
    async def get_result(self, item_id: str) -> Optional[Dict[str, Any]]:
        """Get the result for a specific item"""
        return self._results.get(item_id)
    
    async def cleanup(self) -> None:
        """Process any remaining items before cleanup"""
        if self._batch_queue:
            await self._process_current_batch()
        await super().cleanup()