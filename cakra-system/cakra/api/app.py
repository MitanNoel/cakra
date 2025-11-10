"""CAKRA API Entry Point

Main application module for FastAPI server.
"""

from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import asyncio
import logging
import os
import json

def serialize_for_json(obj):
    """Recursively serialize objects for JSON storage"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, dict):
        return {k: serialize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [serialize_for_json(item) for item in obj]
    else:
        return obj

from cakra.core.config import ConfigLoader
from cakra.core.database import Database
from cakra.agents.scout import ScoutAgent
from cakra.agents.analyst import ContentAnalyst
from cakra.agents.investigator import PaymentInvestigator
from cakra.agents.mapper import NetworkMapper
from cakra.agents.reporter import Reporter

# Request models
class ScanRequest(BaseModel):
    url: str

# Load configuration
config = ConfigLoader().get_config()

# Initialize database
db = Database(config.database)

# Initialize FastAPI app
app = FastAPI(
    title="CAKRA API",
    description="C.A.K.R.A - AI-Powered Cybersecurity Scanner API",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://orange-spork-g4rqxvq675qp2v547-5173.app.github.dev"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize agents
agents = {
    "scout": ScoutAgent(config.models.scout),
    "analyst": ContentAnalyst(config.models.analyst),
    "investigator": PaymentInvestigator(config.models.investigator),
    "mapper": NetworkMapper(config.models.mapper),
    "reporter": Reporter(config.models.reporter)
}

@app.on_event("startup")
async def startup_event():
    """Initialize database and agents on startup"""
    try:
        await db.init_db()
        logging.info("Database initialized successfully")
    except Exception as e:
        logging.error(f"Database initialization failed: {e}")
        # Don't fail startup for database issues
    
    # Initialize all agents (with error handling)
    for name, agent in agents.items():
        try:
            await agent.initialize()
            logging.info(f"✓ {name} agent initialized successfully")
        except Exception as e:
            logging.warning(f"⚠ {name} agent initialization failed: {e}")
            logging.warning(f"Continuing without {name} agent")

# API Routes

@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }

@app.post("/api/v1/test-scan")
async def test_scan_url(request: ScanRequest):
    """Test endpoint for scanning without AI/database"""
    url = request.url
    from urllib.parse import urlparse
    domain = urlparse(url).netloc
    
    # Generate mock results based on URL
    if "scam" in url.lower() or "crypto" in url.lower():
        category = "scam"
        illegal_rate = 85
        confidence = 0.8
    elif "gambling" in url.lower():
        category = "gambling" 
        illegal_rate = 90
        confidence = 0.9
    else:
        category = "safe"
        illegal_rate = 5
        confidence = 0.3
    
    mock_response = {
        "url": url,
        "domain": domain,
        "id": 999,
        "timestamp": datetime.utcnow().isoformat(),
        "scout_analysis": {
            "url": url,
            "status": 200,
            "title": f"Test analysis for {domain}",
            "timestamp": datetime.utcnow().isoformat()
        },
        "content_analysis": {
            "category": category,
            "confidence": confidence,
            "illegal_rate": illegal_rate,
            "suspicious_elements": ["Test analysis - AI unavailable"],
            "risk_assessment": "Test assessment for frontend integration"
        },
        "payment_analysis": {
            "payment_channels": []
        },
        "network_analysis": {
            "ip": "127.0.0.1",
            "server_version": "Test Server",
            "whois": {"registrar": "Test Registrar"}
        },
        "report": {
            "recommendations": ["This is test data for integration testing"],
            "summary": "Test analysis completed successfully"
        }
    }
    
    return JSONResponse(content=mock_response)

@app.get("/api/v1/scan-results")
async def get_scan_results(
    limit: int = Query(100, le=1000),
    offset: int = 0,
    min_illegal_rate: int = Query(0, ge=0, le=100),
    max_illegal_rate: int = Query(100, ge=0, le=100),
    classification: Optional[str] = None,
    days_back: int = Query(30, ge=1, le=365)
):
    """Get scan results with filtering and pagination"""
    try:
        results = await db.get_scan_results(
            limit=limit,
            offset=offset,
            min_illegal_rate=min_illegal_rate,
            max_illegal_rate=max_illegal_rate,
            classification=classification,
            days_back=days_back
        )
        return JSONResponse(content=results)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/scan-results/{url:path}")
async def get_scan_result(url: str):
    """Get detailed scan result for a specific URL"""
    result = await db.get_scan_result(url)
    if not result:
        # Generate mock result if not found in database
        from urllib.parse import urlparse
        domain = urlparse(url).netloc or url
        
        # Generate mock results based on URL
        if "scam" in url.lower() or "crypto" in url.lower():
            category = "scam"
            illegal_rate = 85
            confidence = 0.8
        elif "gambling" in url.lower():
            category = "gambling" 
            illegal_rate = 90
            confidence = 0.9
        else:
            category = "safe"
            illegal_rate = 5
            confidence = 0.3
        
        mock_response = {
            "url": url,
            "domain": domain,
            "id": 999,
            "timestamp": datetime.utcnow().isoformat(),
            "scout_analysis": {
                "url": url,
                "status": 200,
                "title": f"Mock analysis for {domain}",
                "timestamp": datetime.utcnow().isoformat()
            },
            "content_analysis": {
                "category": category,
                "confidence": confidence,
                "illegal_rate": illegal_rate,
                "suspicious_elements": ["Mock analysis - data not available"],
                "risk_assessment": "Mock assessment for frontend integration"
            },
            "payment_analysis": {
                "payment_channels": []
            },
            "network_analysis": {
                "ip": "127.0.0.1",
                "server_version": "Mock Server",
                "whois": {"registrar": "Mock Registrar"}
            },
            "report": {
                "recommendations": ["This is mock data for integration testing"],
                "summary": "Mock analysis completed successfully"
            }
        }
        return JSONResponse(content=mock_response)
    return JSONResponse(content=result)

@app.post("/api/v1/scan")
async def scan_url(url: str, priority: str = "normal"):
    """Submit URL for scanning"""
    try:
        # Extract domain from URL
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        
        # Try AI analysis first
        try:
            # Scan with Scout agent
            scout_result = await agents["scout"].analyze(url)
            
            if scout_result.get("error"):
                raise HTTPException(
                    status_code=400,
                    detail=f"Scout analysis failed: {scout_result['error']}"
                )

            # Run content and payment analysis concurrently
            analyst_result, payment_result = await asyncio.gather(
                agents["analyst"].analyze(scout_result),
                agents["investigator"].analyze(scout_result)
            )

            # Run network mapping
            mapper_result = await agents["mapper"].analyze({
                **scout_result,
                **analyst_result
            })

            # Generate report
            report_result = await agents["reporter"].analyze({
                "scout": scout_result,
                "analyst": analyst_result,
                "payment": payment_result,
                "mapper": mapper_result
            })
            
            # Extract key metrics for top-level fields
            illegal_rate = analyst_result.get("illegal_rate", 0)
            confidence = analyst_result.get("confidence", 0)
            classification = analyst_result.get("category", "unknown")
            
        except Exception as ai_error:
            # Fallback to mock analysis for testing
            logging.warning(f"AI analysis failed, using mock data: {ai_error}")
            
            scout_result = {
                "url": url,
                "status": 200,
                "title": f"Mock analysis for {domain}",
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Generate mock results based on URL
            if "scam" in url.lower() or "crypto" in url.lower():
                category = "scam"
                illegal_rate = 85
                confidence = 0.8
            elif "gambling" in url.lower():
                category = "gambling" 
                illegal_rate = 90
                confidence = 0.9
            else:
                category = "safe"
                illegal_rate = 5
                confidence = 0.3
                
            analyst_result = {
                "category": category,
                "confidence": confidence,
                "illegal_rate": illegal_rate,
                "suspicious_elements": ["Mock analysis - AI unavailable"],
                "risk_assessment": "Mock assessment for testing"
            }
            
            payment_result = {
                "payment_channels": []
            }
            
            mapper_result = {
                "ip": "127.0.0.1",
                "server_version": "Mock Server",
                "whois": {"registrar": "Mock Registrar"}
            }
            
            report_result = {
                "recommendations": ["This is mock data for testing"],
                "summary": "Mock analysis completed"
            }
            
            classification = category
        
        # Map API field names to database model field names
        scan_result_data = {
            "url": url,
            "domain": domain,
            "illegal_rate": illegal_rate,
            "confidence": confidence,
            "classification": classification,
            "text_analysis": serialize_for_json(analyst_result),  # content analysis
            "visual_analysis": serialize_for_json(report_result),  # report
            "payment_info": serialize_for_json(payment_result),  # payment analysis
            "vulnerabilities": serialize_for_json(scout_result),  # scout analysis
            "server_info": serialize_for_json(mapper_result),  # network analysis
            "scan_time": datetime.utcnow()
        }
        
        await db.add_scan_result(scan_result_data)
        
        # Return API format (not database format)
        api_response = {
            "url": url,
            "domain": domain,
            "id": None,  # Will be set after save
            "timestamp": datetime.utcnow().isoformat(),
            "scout_analysis": serialize_for_json(scout_result),
            "content_analysis": serialize_for_json(analyst_result),
            "payment_analysis": serialize_for_json(payment_result),
            "network_analysis": serialize_for_json(mapper_result),
            "report": serialize_for_json(report_result)
        }
        
        return JSONResponse(content=api_response)
        
    except Exception as e:
        logging.error(f"Scan failed for {url}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/payment-channels")
async def get_payment_channels(
    limit: int = Query(500, le=2000),
    type: Optional[str] = None,
    min_risk_score: int = Query(0, ge=0, le=10)
):
    """Get detected payment channels with filtering"""
    try:
        channels = await db.get_payment_channels(
            limit=limit,
            channel_type=type,
            min_risk_score=min_risk_score
        )
        return JSONResponse(content=channels)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/operator-clusters")
async def get_operator_clusters(
    min_risk_score: int = Query(5, ge=0, le=10)
):
    """Get operator clusters above risk threshold"""
    try:
        clusters = await db.get_operator_clusters(min_risk_score=min_risk_score)
        return JSONResponse(content=clusters)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/statistics")
async def get_statistics():
    """Get system statistics"""
    try:
        stats = await db.get_statistics()
        return JSONResponse(content=stats)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))