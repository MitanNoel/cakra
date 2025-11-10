"""CAKRA - Database Management

Handles database operations using SQLAlchemy with async support and connection pooling.
"""

import asyncio
from datetime import datetime, timedelta
from pathlib import Path
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
        database_url = self._prepare_database_url(config.url)
        self.engine = create_async_engine(
            database_url,
            pool_size=config.pool_size,
            max_overflow=config.max_overflow,
            echo=config.echo
        )
        self.async_session = async_sessionmaker(
            self.engine, expire_on_commit=False
        )

    def _prepare_database_url(self, url: str) -> str:
        """Normalize SQLite URLs so relative paths resolve reliably."""
        if not url.startswith("sqlite"):
            return url

        driver, separator, remainder = url.partition(":///")
        if not separator or remainder.startswith(":memory:"):
            return url

        path = Path(remainder)
        if not path.is_absolute():
            base_dir = Path(__file__).resolve().parents[2]
            path = (base_dir / path).resolve()

        if path.parent:
            path.parent.mkdir(parents=True, exist_ok=True)

        return f"{driver}:///{path.as_posix()}"
    
    def _serialize_for_json(self, obj):
        """Recursively serialize objects for JSON storage"""
        from datetime import datetime
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, dict):
            return {k: self._serialize_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._serialize_for_json(item) for item in obj]
        else:
            return obj
    
    def _deep_serialize(self, obj):
        """Deep serialize an entire object/dict for database storage"""
        if isinstance(obj, dict):
            return {k: self._deep_serialize(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._deep_serialize(item) for item in obj]
        else:
            return self._serialize_for_json(obj)
    
    async def init_db(self):
        """Initialize database schema"""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    
    async def add_scan_result(self, result: Dict[str, Any]) -> ScanResult:
        """Add a new scan result to the database"""
        # Extract datetime fields before serialization
        datetime_fields = ['scan_time', 'last_updated']
        datetime_values = {}
        for field in datetime_fields:
            if field in result:
                datetime_values[field] = result.pop(field)
        
        # Deep serialize the remaining fields
        serialized_result = self._deep_serialize(result)
        
        # Add back datetime fields
        serialized_result.update(datetime_values)
        
        async with self.async_session() as session:
            scan_result = ScanResult(**serialized_result)
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
            query = select(ScanResult).where(ScanResult.scan_time >= cutoff)

            if classification:
                query = query.where(ScanResult.classification == classification)

            query = query.where(ScanResult.illegal_rate >= min_illegal_rate)
            query = query.where(ScanResult.illegal_rate <= max_illegal_rate)

            query = query.offset(offset).limit(limit).order_by(ScanResult.scan_time.desc())
            result = await session.execute(query)

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

            channels = result.scalars().all()
            return [self._payment_channel_to_dict(pc) for pc in channels]

    async def get_statistics(self) -> Dict[str, Any]:
        """Get system statistics"""
        async with self.async_session() as session:
            # Total scans
            total_scans_result = await session.execute(
                select(func.count(ScanResult.id))
            )
            total_scans = total_scans_result.scalar() or 0

            # Threats detected (illegal_rate > 50)
            threats_result = await session.execute(
                select(func.count(ScanResult.id)).where(ScanResult.illegal_rate > 50)
            )
            threats_detected = threats_result.scalar() or 0

            # Successful scans (no error)
            success_result = await session.execute(
                select(func.count(ScanResult.id)).where(ScanResult.error.is_(None))
            )
            successful_scans = success_result.scalar() or 0

            # Recent scans (last 24 hours)
            yesterday = datetime.utcnow() - timedelta(hours=24)
            recent_result = await session.execute(
                select(func.count(ScanResult.id)).where(ScanResult.scan_time >= yesterday)
            )
            recent_scans = recent_result.scalar() or 0

            # Calculate success rate
            success_rate = (successful_scans / total_scans * 100) if total_scans > 0 else 0

            return {
                "total_scans": total_scans,
                "threats_detected": threats_detected,
                "payment_channels": 0,  # TODO: implement payment channel count
                "success_rate": round(success_rate, 2),
                "recent_scans": recent_scans,
                "last_updated": datetime.utcnow().isoformat()
            }

    def _scan_result_to_dict(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Convert ScanResult object to dictionary"""
        content_analysis = scan_result.text_analysis or {}
        payment_info = scan_result.payment_info or {}
        network_info = scan_result.server_info or {}
        vulnerabilities = scan_result.vulnerabilities or {}
        visual_analysis = scan_result.visual_analysis or {}

        confidence = scan_result.confidence or 0
        if confidence and confidence <= 1:
            confidence *= 100

        return {
            "id": scan_result.id,
            "url": scan_result.url,
            "domain": scan_result.domain or scan_result.url,
            "timestamp": (scan_result.scan_time or datetime.utcnow()).isoformat(),
            "risk_score": scan_result.illegal_rate or 0,
            "content_analysis": {
                "category": scan_result.classification or content_analysis.get("category", "unknown"),
                "confidence": confidence,
                "illegal_rate": scan_result.illegal_rate or content_analysis.get("illegal_rate", 0),
                **{k: v for k, v in content_analysis.items() if k not in {"category", "confidence", "illegal_rate"}}
            },
            "payment_analysis": {
                "payment_channels": payment_info.get("payment_channels", []),
                **{k: v for k, v in payment_info.items() if k != "payment_channels"}
            },
            "network_analysis": {
                **network_info,
                "whois": scan_result.whois_data,
                "linked_domains": scan_result.linked_domains
            },
            "scout_analysis": vulnerabilities,
            "report": visual_analysis,
            "error": scan_result.error
        }

    def _payment_channel_to_dict(self, channel: PaymentChannel) -> Dict[str, Any]:
        """Convert PaymentChannel object to dictionary"""
        metadata = channel.channel_metadata or {}

        return {
            "id": channel.id,
            "identifier": channel.identifier,
            "type": channel.channel_type,
            "risk_score": channel.risk_score or metadata.get("risk_score", 0),
            "associated_urls": channel.associated_urls or [],
            "first_detected": (channel.first_seen or datetime.utcnow()).isoformat(),
            "last_updated": (channel.last_seen or datetime.utcnow()).isoformat(),
            "detection_count": metadata.get("detection_count", 1),
            "confidence": metadata.get("confidence", 85)
        }