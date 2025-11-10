"""CAKRA - Database Management

Handles database operations using SQLAlchemy with async support and connection pooling.
"""

import asyncio
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from sqlalchemy.ext.asyncio import (
    create_async_engine, AsyncSession, async_sessionmaker
)
from sqlalchemy import select, update, delete, func

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
    
    async def get_scan_results(
        self,
        limit: int = 100,
        offset: int = 0,
        min_illegal_rate: int = 0,
        max_illegal_rate: int = 100,
        classification: Optional[str] = None,
        days_back: int = 30
    ) -> List[Dict[str, Any]]:
        """Get scan results with filtering and pagination"""
        cutoff = datetime.utcnow() - timedelta(days=days_back)
        
        async with self.async_session() as session:
            query = select(ScanResult).where(ScanResult.timestamp >= cutoff)
            
            if classification:
                # This would need to be adapted based on your actual data structure
                pass
            
            query = query.offset(offset).limit(limit).order_by(ScanResult.timestamp.desc())
            result = await session.execute(query)
            
            # Convert to dict format for JSON serialization
            scan_results = result.scalars().all()
            return [self._scan_result_to_dict(sr) for sr in scan_results]
    
    async def get_payment_channels(
        self,
        limit: int = 500,
        channel_type: Optional[str] = None,
        min_risk_score: int = 0
    ) -> List[Dict[str, Any]]:
        """Get payment channels with filtering"""
        async with self.async_session() as session:
            query = select(PaymentChannel).where(PaymentChannel.risk_score >= min_risk_score)
            
            if channel_type:
                query = query.where(PaymentChannel.channel_type == channel_type)
            
            query = query.limit(limit).order_by(PaymentChannel.risk_score.desc())
            result = await session.execute(query)
            
            # Convert to dict format for JSON serialization
            channels = result.scalars().all()
            return [self._payment_channel_to_dict(pc) for pc in channels]
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get system statistics"""
        async with self.async_session() as session:
            # Count total scans
            total_scans_result = await session.execute(
                select(func.count(ScanResult.id))
            )
            total_scans = total_scans_result.scalar() or 0
            
            # Count payment channels
            payment_channels_result = await session.execute(
                select(func.count(PaymentChannel.id))
            )
            payment_channels = payment_channels_result.scalar() or 0
            
            # For now, return mock statistics since we don't have data
            return {
                "total_scans": total_scans,
                "threats_detected": 0,  # Would need to calculate based on risk scores
                "payment_channels": payment_channels,
                "safe_sites": 0,  # Would need to calculate based on classifications
                "last_updated": datetime.utcnow().isoformat()
            }
    
    def _scan_result_to_dict(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Convert ScanResult object to dictionary"""
        return {
            "id": scan_result.id,
            "url": scan_result.url,
            "timestamp": scan_result.timestamp.isoformat() if scan_result.timestamp else None,
            "risk_score": getattr(scan_result, 'risk_score', 0),
            "content_analysis": getattr(scan_result, 'content_analysis', {}),
            "payment_analysis": getattr(scan_result, 'payment_analysis', {}),
            "network_analysis": getattr(scan_result, 'network_analysis', {}),
            "report": getattr(scan_result, 'report', {})
        }
    
    def _payment_channel_to_dict(self, channel: PaymentChannel) -> Dict[str, Any]:
        """Convert PaymentChannel object to dictionary"""
        return {
            "id": channel.id,
            "identifier": channel.identifier,
            "type": getattr(channel, 'channel_type', 'unknown'),
            "provider": getattr(channel, 'provider', None),
            "risk_score": channel.risk_score,
            "associated_urls": getattr(channel, 'associated_urls', []),
            "first_detected": channel.first_detected.isoformat() if hasattr(channel, 'first_detected') and channel.first_detected else datetime.utcnow().isoformat(),
            "last_updated": getattr(channel, 'last_updated', datetime.utcnow()).isoformat() if hasattr(channel, 'last_updated') else datetime.utcnow().isoformat(),
            "detection_count": getattr(channel, 'detection_count', 1),
            "confidence": getattr(channel, 'confidence', 85)
        }