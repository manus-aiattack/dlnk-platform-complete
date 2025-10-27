"""
Base Service Layer
Provides common functionality for all services
"""

from typing import Generic, TypeVar, Type, Optional, List, Dict, Any
from abc import ABC, abstractmethod
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

T = TypeVar('T')


class BaseService(ABC, Generic[T]):
    """
    Base Service Class
    
    Provides common CRUD operations and business logic structure
    """
    
    def __init__(self, db):
        """
        Initialize service
        
        Args:
            db: Database connection
        """
        self.db = db
        self.logger = logger
    
    @abstractmethod
    def get_model(self) -> Type[T]:
        """Get the model class for this service"""
        pass
    
    @abstractmethod
    def get_table_name(self) -> str:
        """Get the table name for this service"""
        pass
    
    async def create(self, data: Dict[str, Any]) -> T:
        """
        Create a new record
        
        Args:
            data: Record data
        
        Returns:
            Created record
        """
        try:
            # Add timestamps
            data['created_at'] = datetime.utcnow()
            data['updated_at'] = datetime.utcnow()
            
            # Insert into database
            query = self._build_insert_query(data)
            result = await self.db.execute(query, data)
            
            # Get created record
            record_id = result.get('id')
            return await self.get_by_id(record_id)
        
        except Exception as e:
            self.logger.error(f"Error creating record: {e}")
            raise
    
    async def get_by_id(self, record_id: Any) -> Optional[T]:
        """
        Get record by ID
        
        Args:
            record_id: Record ID
        
        Returns:
            Record or None if not found
        """
        try:
            query = f"SELECT * FROM {self.get_table_name()} WHERE id = :id"
            result = await self.db.fetch_one(query, {'id': record_id})
            
            if result:
                return self._map_to_model(result)
            return None
        
        except Exception as e:
            self.logger.error(f"Error getting record by ID: {e}")
            raise
    
    async def get_all(
        self,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 100,
        offset: int = 0,
        order_by: str = 'created_at DESC'
    ) -> List[T]:
        """
        Get all records with optional filtering
        
        Args:
            filters: Filter conditions
            limit: Maximum number of records
            offset: Number of records to skip
            order_by: Order by clause
        
        Returns:
            List of records
        """
        try:
            query = f"SELECT * FROM {self.get_table_name()}"
            params = {}
            
            # Add filters
            if filters:
                where_clauses = []
                for key, value in filters.items():
                    where_clauses.append(f"{key} = :{key}")
                    params[key] = value
                
                if where_clauses:
                    query += " WHERE " + " AND ".join(where_clauses)
            
            # Add order by
            query += f" ORDER BY {order_by}"
            
            # Add limit and offset
            query += f" LIMIT :limit OFFSET :offset"
            params['limit'] = limit
            params['offset'] = offset
            
            results = await self.db.fetch_all(query, params)
            
            return [self._map_to_model(result) for result in results]
        
        except Exception as e:
            self.logger.error(f"Error getting all records: {e}")
            raise
    
    async def update(self, record_id: Any, data: Dict[str, Any]) -> Optional[T]:
        """
        Update a record
        
        Args:
            record_id: Record ID
            data: Updated data
        
        Returns:
            Updated record or None if not found
        """
        try:
            # Add updated timestamp
            data['updated_at'] = datetime.utcnow()
            
            # Build update query
            set_clauses = []
            params = {'id': record_id}
            
            for key, value in data.items():
                set_clauses.append(f"{key} = :{key}")
                params[key] = value
            
            query = f"""
                UPDATE {self.get_table_name()}
                SET {', '.join(set_clauses)}
                WHERE id = :id
            """
            
            await self.db.execute(query, params)
            
            # Get updated record
            return await self.get_by_id(record_id)
        
        except Exception as e:
            self.logger.error(f"Error updating record: {e}")
            raise
    
    async def delete(self, record_id: Any) -> bool:
        """
        Delete a record
        
        Args:
            record_id: Record ID
        
        Returns:
            True if deleted, False if not found
        """
        try:
            query = f"DELETE FROM {self.get_table_name()} WHERE id = :id"
            result = await self.db.execute(query, {'id': record_id})
            
            return result.get('rowcount', 0) > 0
        
        except Exception as e:
            self.logger.error(f"Error deleting record: {e}")
            raise
    
    async def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """
        Count records
        
        Args:
            filters: Filter conditions
        
        Returns:
            Number of records
        """
        try:
            query = f"SELECT COUNT(*) as count FROM {self.get_table_name()}"
            params = {}
            
            # Add filters
            if filters:
                where_clauses = []
                for key, value in filters.items():
                    where_clauses.append(f"{key} = :{key}")
                    params[key] = value
                
                if where_clauses:
                    query += " WHERE " + " AND ".join(where_clauses)
            
            result = await self.db.fetch_one(query, params)
            
            return result.get('count', 0) if result else 0
        
        except Exception as e:
            self.logger.error(f"Error counting records: {e}")
            raise
    
    async def exists(self, record_id: Any) -> bool:
        """
        Check if record exists
        
        Args:
            record_id: Record ID
        
        Returns:
            True if exists, False otherwise
        """
        record = await self.get_by_id(record_id)
        return record is not None
    
    def _build_insert_query(self, data: Dict[str, Any]) -> str:
        """Build INSERT query"""
        columns = ', '.join(data.keys())
        values = ', '.join([f':{key}' for key in data.keys()])
        
        return f"""
            INSERT INTO {self.get_table_name()} ({columns})
            VALUES ({values})
            RETURNING id
        """
    
    def _map_to_model(self, data: Dict[str, Any]) -> T:
        """
        Map database result to model
        
        Override this method to customize mapping
        """
        model_class = self.get_model()
        return model_class(**data)


class CacheableService(BaseService[T]):
    """
    Service with caching support
    """
    
    def __init__(self, db, cache=None):
        """
        Initialize service with cache
        
        Args:
            db: Database connection
            cache: Cache instance (Redis, etc.)
        """
        super().__init__(db)
        self.cache = cache
        self.cache_ttl = 300  # 5 minutes default
    
    def _get_cache_key(self, record_id: Any) -> str:
        """Get cache key for record"""
        return f"{self.get_table_name()}:{record_id}"
    
    async def get_by_id(self, record_id: Any) -> Optional[T]:
        """Get record by ID with caching"""
        if self.cache:
            # Try cache first
            cache_key = self._get_cache_key(record_id)
            cached = await self.cache.get(cache_key)
            
            if cached:
                return self._map_to_model(cached)
        
        # Get from database
        record = await super().get_by_id(record_id)
        
        # Cache result
        if self.cache and record:
            cache_key = self._get_cache_key(record_id)
            await self.cache.set(cache_key, record, ttl=self.cache_ttl)
        
        return record
    
    async def update(self, record_id: Any, data: Dict[str, Any]) -> Optional[T]:
        """Update record and invalidate cache"""
        record = await super().update(record_id, data)
        
        # Invalidate cache
        if self.cache:
            cache_key = self._get_cache_key(record_id)
            await self.cache.delete(cache_key)
        
        return record
    
    async def delete(self, record_id: Any) -> bool:
        """Delete record and invalidate cache"""
        result = await super().delete(record_id)
        
        # Invalidate cache
        if self.cache:
            cache_key = self._get_cache_key(record_id)
            await self.cache.delete(cache_key)
        
        return result

