"""CAKRA - Database Management

Handles database operations using SQLAlchemy with async support and connection pooling.
"""

import asyncio
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from sqlalchemy.ext.asyncio import (
    create_async_engine, AsyncSession, async_sessionmaker
)
from sqlalchemy import select, update, delete

from .models import Base, ScanResult, PaymentChannel, OperatorCluster, FeedbackEntry
from .config import DatabaseConfig

class Database:
    """Async database manager with connection pooling"""
    
    def __init__(self, config: DatabaseConfig):
        self.config = config
        self.engine = create_async_engine(
            config.url,
            pool_size=config.pool_size,
            max_overflow=config.max_overflow,
            echo=config.echo
        )
        self.async_session = async_sessionmaker(
            self.engine, expire_on_commit=False
        )
    
    async def init_db(self):
        """Initialize database schema"""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    
    async def add_scan_result(self, result: Dict[str, Any]) -> ScanResult:
        """Add a new scan result to the database"""
        async with self.async_session() as session:
            scan_result = ScanResult(**result)
            session.add(scan_result)
            await session.commit()
            return scan_result
    
    async def get_scan_result(self, url: str) -> Optional[ScanResult]:
        """Get scan result by URL"""
        async with self.async_session() as session:
            result = await session.execute(
                select(ScanResult).where(ScanResult.url == url)
            )
            return result.scalars().first()
    
    async def update_scan_result(self, url: str, updates: Dict[str, Any]) -> bool:
        """Update existing scan result"""
        async with self.async_session() as session:
            result = await session.execute(
                update(ScanResult)
                .where(ScanResult.url == url)
                .values(**updates)
            )
            await session.commit()
            return result.rowcount > 0
    
    async def add_payment_channel(self, channel: Dict[str, Any]) -> PaymentChannel:
        """Add a new payment channel"""
        async with self.async_session() as session:
            payment_channel = PaymentChannel(**channel)
            session.add(payment_channel)
            await session.commit()
            return payment_channel
    
    async def get_high_risk_channels(
        self, min_risk_score: int = 7
    ) -> List[PaymentChannel]:
        """Get payment channels above risk threshold"""
        async with self.async_session() as session:
            result = await session.execute(
                select(PaymentChannel)
                .where(PaymentChannel.risk_score >= min_risk_score)
                .order_by(PaymentChannel.risk_score.desc())
            )
            return result.scalars().all()
    
    async def create_operator_cluster(self, cluster: Dict[str, Any]) -> OperatorCluster:
        """Create a new operator cluster"""
        async with self.async_session() as session:
            operator_cluster = OperatorCluster(**cluster)
            session.add(operator_cluster)
            await session.commit()
            return operator_cluster
    
    async def get_operator_clusters(
        self, min_risk_score: Optional[int] = None
    ) -> List[OperatorCluster]:
        """Get operator clusters optionally filtered by risk score"""
        async with self.async_session() as session:
            query = select(OperatorCluster)
            if min_risk_score is not None:
                query = query.where(OperatorCluster.risk_score >= min_risk_score)
            result = await session.execute(query)
            return result.scalars().all()
    
    async def add_feedback(self, feedback: Dict[str, Any]) -> FeedbackEntry:
        """Add user feedback for a scan result"""
        async with self.async_session() as session:
            feedback_entry = FeedbackEntry(**feedback)
            session.add(feedback_entry)
            await session.commit()
            return feedback_entry
    
    async def get_recent_feedback(
        self, days: int = 30
    ) -> List[FeedbackEntry]:
        """Get recent feedback entries"""
        cutoff = datetime.utcnow() - timedelta(days=days)
        async with self.async_session() as session:
            result = await session.execute(
                select(FeedbackEntry)
                .where(FeedbackEntry.created_at >= cutoff)
                .order_by(FeedbackEntry.created_at.desc())
            )
            return result.scalars().all()