"""CAKRA - Core Database Models

This module defines the SQLAlchemy models for the CAKRA scanning system.
"""

from datetime import datetime
from typing import List, Optional
from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, 
    ForeignKey, Text, JSON, Float
)
from sqlalchemy.orm import DeclarativeBase, relationship

class Base(DeclarativeBase):
    pass

class ScanResult(Base):
    """Stores the results of website scans"""
    __tablename__ = "scan_results"
    
    id = Column(Integer, primary_key=True)
    url = Column(String, unique=True, nullable=False, index=True)
    domain = Column(String, nullable=False, index=True)
    illegal_rate = Column(Integer)
    confidence = Column(Float)
    classification = Column(String, index=True)
    
    # Analysis Results
    text_analysis = Column(JSON)
    visual_analysis = Column(JSON)
    payment_info = Column(JSON)
    vulnerabilities = Column(JSON)
    
    # Network Info
    server_info = Column(JSON)
    whois_data = Column(JSON)
    linked_domains = Column(JSON)
    
    # Metadata
    scan_time = Column(DateTime, default=datetime.utcnow)
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    error = Column(Text)
    is_active = Column(Boolean, default=True)

class PaymentChannel(Base):
    """Tracks payment channels across illegal websites"""
    __tablename__ = "payment_channels"
    
    id = Column(Integer, primary_key=True)
    channel_type = Column(String, nullable=False, index=True)  # qris, bank, ewallet, etc
    identifier = Column(String, nullable=False, unique=True)
    risk_score = Column(Integer)
    associated_urls = Column(JSON)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    channel_metadata = Column(JSON)

class OperatorCluster(Base):
    """Groups of related illegal websites sharing infrastructure/payment channels"""
    __tablename__ = "operator_clusters"
    
    id = Column(Integer, primary_key=True)
    name = Column(String)
    risk_score = Column(Integer)
    domains = Column(JSON)
    payment_channels = Column(JSON)
    infrastructure = Column(JSON)
    evidence = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class FeedbackEntry(Base):
    """User feedback on scan results for improving accuracy"""
    __tablename__ = "feedback"
    
    id = Column(Integer, primary_key=True)
    scan_result_id = Column(Integer, ForeignKey("scan_results.id"))
    feedback_type = Column(String)  # correct, incorrect, false_positive, false_negative
    comment = Column(Text)
    original_classification = Column(String)
    original_confidence = Column(Float)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    scan_result = relationship("ScanResult", backref="feedback_entries")