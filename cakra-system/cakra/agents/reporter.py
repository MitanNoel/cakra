"""CAKRA - Intelligence Reporter Agent

Generates structured intelligence reports using LLaMa model.
"""

from typing import Dict, List, Any
import asyncio
import logging
from datetime import datetime
import json
import ollama

from .base import Agent

from ..core.config import ReporterConfig

class Reporter(Agent):
    """Generates intelligence reports from scan data"""
    
    def __init__(self, config: ReporterConfig):
        super().__init__(config)
        self.report_model = config.model
        self.max_tokens = config.max_tokens
        self.temperature = config.temperature
        
        # Report generation prompts
        self.report_prompt = """
        Generate a detailed intelligence report about potentially illegal websites and operators.
        
        Data to analyze:
        {data}
        
        Structure the report with these sections:
        1. Executive Summary
        2. Key Findings
        3. Technical Analysis
        4. Infrastructure Connections
        5. Payment Channels
        6. Risk Assessment
        7. Recommendations
        
        Format the report in Markdown.
        """
        
        self.evidence_prompt = """
        Analyze the evidence provided and rate the confidence level of illegal activities.
        
        Evidence:
        {evidence}
        
        Consider:
        - Content analysis results
        - Network connections
        - Payment systems
        - Infrastructure patterns
        
        Provide:
        1. Confidence rating (0-100)
        2. Key evidence points
        3. Potential false positives
        4. Recommended actions
        """
    
    async def initialize(self) -> None:
        """Initialize the reporting model"""
        try:
            # Run the synchronous ollama.generate in a thread pool
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: ollama.generate(
                    model=self.report_model,
                    prompt="Test.",
                    options={"temperature": 0}
                )
            )
            if not response or not response.get("response"):
                raise RuntimeError("Report model not responding")
            self.is_initialized = True
        except Exception as e:
            logging.error(f"Reporter initialization error: {str(e)}")
            raise
    
    async def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate intelligence report from scan data"""
        try:
            # Generate main report and evidence analysis concurrently
            report, evidence = await asyncio.gather(
                self._generate_report(data),
                self._analyze_evidence(data)
            )
            
            return {
                "report": report,
                "evidence_analysis": evidence,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logging.error(f"Report generation error: {str(e)}")
            return {
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def _generate_report(self, data: Dict[str, Any]) -> str:
        """Generate the main intelligence report"""
        try:
            # Prepare data for report generation
            report_data = {
                "url": data.get("url"),
                "scan_results": data.get("scan_results", {}),
                "network_analysis": data.get("network_analysis", {}),
                "payment_channels": data.get("payment_channels", {})
            }
            
            prompt = self.report_prompt.format(
                data=json.dumps(report_data, indent=2)
            )
            
            # Run the synchronous ollama.generate in a thread pool
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: ollama.generate(
                    model=self.report_model,
                    prompt=prompt,
                    options={
                        "temperature": self.temperature,
                        "max_tokens": self.max_tokens
                    }
                )
            )
            
            return response.get("response", "Error generating report")
            
        except Exception as e:
            logging.error(f"Report generation error: {str(e)}")
            return f"Error generating report: {str(e)}"
    
    async def _analyze_evidence(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze and rate evidence strength"""
        try:
            # Prepare evidence for analysis
            evidence_data = {
                "content_analysis": {
                    "text_analysis": data.get("scan_results", {}).get("text_analysis", {}),
                    "vision_analysis": data.get("scan_results", {}).get("vision_analysis", {})
                },
                "infrastructure": data.get("network_analysis", {}),
                "payment_info": data.get("payment_channels", {})
            }
            
            prompt = self.evidence_prompt.format(
                evidence=json.dumps(evidence_data, indent=2)
            )
            
            # Run the synchronous ollama.generate in a thread pool
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: ollama.generate(
                    model=self.report_model,
                    prompt=prompt,
                    options={
                        "temperature": self.temperature
                    }
                )
            )
            
            # Parse the response into structured format
            try:
                evidence_analysis = json.loads(response.get("response", "{}"))
            except json.JSONDecodeError:
                evidence_analysis = {
                    "confidence": 0,
                    "key_points": ["Error parsing evidence analysis"],
                    "false_positives": [],
                    "recommendations": []
                }
            
            return evidence_analysis
            
        except Exception as e:
            logging.error(f"Evidence analysis error: {str(e)}")
            return {
                "error": str(e),
                "confidence": 0,
                "key_points": [],
                "false_positives": [],
                "recommendations": []
            }
    
    def _format_report(self, content: str) -> str:
        """Format report content with proper Markdown"""
        try:
            # Add metadata
            metadata = {
                "generated_at": datetime.utcnow().isoformat(),
                "model": self.report_model,
                "version": "1.0"
            }
            
            return f"""---
{json.dumps(metadata, indent=2)}
---

{content}
"""
        except Exception as e:
            logging.error(f"Report formatting error: {str(e)}")
            return content
    
    async def cleanup(self) -> None:
        """Clean up resources"""
        self.is_initialized = False