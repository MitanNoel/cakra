"""CAKRA - Content Analysis Agent

Analyzes website content using Ollama models for text and image classification.
"""

from typing import Dict, List, Any, Optional
import asyncio
import base64
import io
import logging
from PIL import Image
import ollama

from .base import BatchAgent
from ..core.config import AnalystConfig

class ContentAnalyst(BatchAgent):
    """Analyzes website content using AI models"""
    
    def __init__(self, config: AnalystConfig):
        super().__init__(config, batch_size=config.batch_size)
        self.text_model = config.text_model
        self.vision_model = config.vision_model
        self.max_tokens = config.max_tokens
        self.temperature = config.temperature
        
        # Classification categories
        self.categories = [
            "gambling", "scam", "malware", "phishing",
            "defacement", "illegal_content", "safe"
        ]
        
        # Default prompts
        self.text_prompt = """
        Analyze the following website content and classify it into one of these categories:
        {categories}
        
        Also identify any suspicious or illegal activities, and estimate the likelihood 
        of the site being malicious (0-100%).
        
        Content to analyze:
        {content}
        
        Provide your analysis in JSON format with these fields:
        - category: The main category
        - confidence: Confidence score (0-100)
        - suspicious_elements: List of suspicious elements found
        - risk_assessment: Detailed risk evaluation
        """
        
        self.vision_prompt = """
        Analyze this website screenshot and identify any suspicious or illegal elements:
        - Gambling or betting interfaces
        - Adult/explicit content
        - Scam indicators
        - Malicious ads
        - Payment systems (especially QRIS codes)
        - Signs of site defacement
        
        Return your analysis in JSON format with:
        - detected_elements: List of suspicious elements
        - risk_level: Low/Medium/High
        - confidence: 0-100
        - details: Detailed explanation
        """
    
    async def initialize(self) -> None:
        """Verify Ollama models are available"""
        try:
            # Test models
            await asyncio.gather(
                self._test_model(self.text_model),
                self._test_model(self.vision_model)
            )
            self.is_initialized = True
        except Exception as e:
            logging.error(f"Model initialization error: {str(e)}")
            raise
    
    async def _test_model(self, model_name: str) -> None:
        """Test if a model is available and responding"""
        # Run the synchronous ollama.generate in a thread pool
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: ollama.generate(
                model=model_name,
                prompt="Test.",
                options={"temperature": 0}
            )
        )
        if not response or not response.get("response"):
            raise RuntimeError(f"Model {model_name} not responding properly")
    
    async def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze website content using both text and vision models"""
        text_content = data.get("text_content", "")
        screenshots = data.get("screenshots", {})
        
        # Run text and vision analysis concurrently
        text_analysis, vision_analysis = await asyncio.gather(
            self._analyze_text(text_content),
            self._analyze_screenshots(screenshots)
        )
        
        # Combine and synthesize results
        combined_analysis = self._synthesize_results(text_analysis, vision_analysis)
        
        return {
            "text_analysis": text_analysis,
            "vision_analysis": vision_analysis,
            "combined_analysis": combined_analysis
        }
    
    async def process_batch(self, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process a batch of items concurrently"""
        return await asyncio.gather(
            *[self.analyze(item) for item in items]
        )
    
    async def _analyze_text(self, content: str) -> Dict[str, Any]:
        """Analyze text content using the text model"""
        if not content:
            return {"error": "No text content provided"}
        
        try:
            prompt = self.text_prompt.format(
                categories=", ".join(self.categories),
                content=content[:self.max_tokens]  # Truncate if too long
            )
            
            # Run the synchronous ollama.generate in a thread pool
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: ollama.generate(
                    model=self.text_model,
                    prompt=prompt,
                    options={
                        "temperature": self.temperature,
                        "max_tokens": self.max_tokens
                    }
                )
            )
            
            return response.get("response", {})
            
        except Exception as e:
            logging.error(f"Text analysis error: {str(e)}")
            return {"error": str(e)}
    
    async def _analyze_screenshots(self, screenshots: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze screenshots using the vision model"""
        if not screenshots:
            return {"error": "No screenshots provided"}
        
        try:
            # Analyze full page screenshot first, fall back to viewport if needed
            screenshot = screenshots.get("full_page") or screenshots.get("viewport")
            if not screenshot:
                return {"error": "No valid screenshots found"}
            
            # Handle both bytes and base64 string formats
            if isinstance(screenshot, str):
                # It's a base64 string, decode it
                import base64
                screenshot_bytes = base64.b64decode(screenshot)
            else:
                # It's already bytes
                screenshot_bytes = screenshot
            
            # Prepare image for vision model
            image = Image.open(io.BytesIO(screenshot_bytes))
            # Resize if needed to meet model requirements
            image.thumbnail((1024, 1024))
            
            # Convert to base64
            buffered = io.BytesIO()
            image.save(buffered, format="JPEG")
            img_base64 = base64.b64encode(buffered.getvalue()).decode()
            
            # Run the synchronous ollama.generate in a thread pool
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: ollama.generate(
                    model=self.vision_model,
                    prompt=[
                        self.vision_prompt,
                        {"type": "image", "data": img_base64}
                    ],
                    options={
                        "temperature": self.temperature
                    }
                )
            )
            
            return response.get("response", {})
            
        except Exception as e:
            logging.error(f"Vision analysis error: {str(e)}")
            return {"error": str(e)}
    
    def _synthesize_results(
        self,
        text_analysis: Dict[str, Any],
        vision_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Combine text and vision analysis into final assessment"""
        
        # Handle errors in either analysis
        if text_analysis.get("error") and vision_analysis.get("error"):
            return {"error": "Both text and vision analysis failed"}
        
        # Extract key metrics
        text_confidence = text_analysis.get("confidence", 0)
        vision_risk = {
            "Low": 25,
            "Medium": 50,
            "High": 75
        }.get(vision_analysis.get("risk_level", "Low"), 0)
        
        # Combine suspicious elements
        suspicious_elements = (
            text_analysis.get("suspicious_elements", []) +
            vision_analysis.get("detected_elements", [])
        )
        
        # Calculate weighted illegal rate
        text_weight = 0.6
        vision_weight = 0.4
        illegal_rate = int(
            (text_confidence * text_weight) +
            (vision_risk * vision_weight)
        )
        
        return {
            "illegal_rate": illegal_rate,
            "confidence": max(text_confidence, vision_risk),
            "suspicious_elements": list(set(suspicious_elements)),
            "category": text_analysis.get("category", "unknown"),
            "risk_assessment": {
                "text_risk": text_analysis.get("risk_assessment"),
                "vision_risk": vision_analysis.get("details")
            }
        }
    
    async def cleanup(self) -> None:
        """Clean up any resources"""
        # Process any remaining items in batch
        await super().cleanup()
        self.is_initialized = False