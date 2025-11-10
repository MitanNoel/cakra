"""CAKRA API Entry Point

Main application module for FastAPI server.
"""

from fastapi import FastAPI, HTTPException, Depends, Query, Request, Form
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import asyncio
import logging
import os

from cakra.core.config import ConfigLoader
from cakra.core.database import Database
from cakra.agents.scout import ScoutAgent
from cakra.agents.analyst import ContentAnalyst
from cakra.agents.investigator import PaymentInvestigator
from cakra.agents.mapper import NetworkMapper
from cakra.agents.reporter import Reporter

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
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Get the web directory path
web_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web")

# Mount static files
app.mount("/static", StaticFiles(directory=os.path.join(web_dir, "static")), name="static")

# Initialize templates
templates = Jinja2Templates(directory=os.path.join(web_dir, "templates"))

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
    await db.init_db()
    
    # Initialize all agents
    for agent in agents.values():
        await agent.initialize()

# Web Routes
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Dashboard page"""
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "page_title": "Dashboard"
    })

@app.get("/scan", response_class=HTMLResponse)
async def scan_page(request: Request):
    """Scan page"""
    return templates.TemplateResponse("scan.html", {
        "request": request,
        "page_title": "Scan URL"
    })

@app.get("/results", response_class=HTMLResponse)
async def results_page(request: Request):
    """Results page"""
    return templates.TemplateResponse("results.html", {
        "request": request,
        "page_title": "Scan Results"
    })

@app.get("/payments", response_class=HTMLResponse)
async def payments_page(request: Request):
    """Payment channels page"""
    return templates.TemplateResponse("payments.html", {
        "request": request,
        "page_title": "Payment Channels"
    })

# API Routes

@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }

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
        raise HTTPException(status_code=404, detail="Scan result not found")
    return JSONResponse(content=result)

@app.post("/api/v1/scan")
async def scan_url(url: str = Form(...), priority: str = Form("normal")):
    """Submit URL for scanning"""
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
        })        # Save results to database
        scan_result = {
            "url": url,
            "scout_analysis": scout_result,
            "content_analysis": analyst_result,
            "payment_analysis": payment_result,
            "network_analysis": mapper_result,
            "report": report_result,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await db.add_scan_result(scan_result)
        
        return JSONResponse(content=scan_result)
        
    except Exception as e:
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