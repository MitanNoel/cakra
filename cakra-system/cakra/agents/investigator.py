"""CAKRA - Payment Investigator Agent

Detects and analyzes payment channels including QRIS codes, bank accounts, and e-wallets.
"""

from typing import Dict, List, Any, Optional
import re
import io
import logging
from datetime import datetime
import pytesseract
from PIL import Image

from .base import Agent

from ..core.config import InvestigatorConfig

class PaymentInvestigator(Agent):
    """Detects and analyzes payment channels in website content"""
    
    def __init__(self, config: InvestigatorConfig):
        super().__init__(config)
        self.tesseract_config = config.tesseract_config
        
        # Regex patterns for different payment channels
        self.patterns = {
            "qris": r"ID\d{16,22}",  # QRIS ID pattern
            "bank_account": {
                "bca": r"\b\d{10,11}\b",
                "mandiri": r"\b\d{13,16}\b",
                "bni": r"\b\d{10}\b",
                "bri": r"\b\d{15}\b"
            },
            "ewallet": {
                "gopay": r"\b08\d{8,11}\b",
                "ovo": r"\b08\d{9,12}\b",
                "dana": r"\b08\d{8,12}\b"
            },
            "phone": r"\b(?:08|\+628)\d{8,11}\b"  # Indonesian phone numbers
        }
    
    async def initialize(self) -> None:
        """Initialize Tesseract OCR if needed"""
        try:
            # Test Tesseract installation
            pytesseract.get_tesseract_version()
            self.is_initialized = True
        except Exception as e:
            logging.error(f"Tesseract initialization error: {str(e)}")
            raise
    
    async def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze content for payment channels"""
        text_content = data.get("text_content", "")
        screenshots = data.get("screenshots", {})
        forms = data.get("forms", [])
        
        results = {
            "qris_codes": [],
            "bank_accounts": [],
            "ewallets": [],
            "phone_numbers": [],
            "forms": [],
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Analyze text content
        self._analyze_text(text_content, results)
        
        # Analyze screenshots for QR codes and text
        await self._analyze_screenshots(screenshots, results)
        
        # Analyze forms for payment-related fields
        self._analyze_forms(forms, results)
        
        # Calculate risk score
        results["risk_score"] = self._calculate_risk_score(results)
        
        return results
    
    def _analyze_text(self, content: str, results: Dict[str, List[str]]) -> None:
        """Analyze text content for payment information"""
        if not content:
            return
            
        # Find QRIS codes
        qris_matches = re.finditer(self.patterns["qris"], content)
        results["qris_codes"].extend(match.group() for match in qris_matches)
        
        # Find bank accounts
        for bank, pattern in self.patterns["bank_account"].items():
            matches = re.finditer(pattern, content)
            results["bank_accounts"].extend({
                "bank": bank,
                "account": match.group()
            } for match in matches)
        
        # Find e-wallet accounts
        for wallet, pattern in self.patterns["ewallet"].items():
            matches = re.finditer(pattern, content)
            results["ewallets"].extend({
                "provider": wallet,
                "number": match.group()
            } for match in matches)
        
        # Find phone numbers
        phone_matches = re.finditer(self.patterns["phone"], content)
        results["phone_numbers"].extend(match.group() for match in phone_matches)
    
    async def _analyze_screenshots(
        self,
        screenshots: Dict[str, bytes],
        results: Dict[str, List[str]]
    ) -> None:
        """Analyze screenshots for payment information using OCR"""
        if not screenshots:
            return
            
        for screenshot_type, screenshot_data in screenshots.items():
            try:
                # Convert screenshot to PIL Image
                image = Image.open(io.BytesIO(screenshot_data))
                
                # Perform OCR
                text = pytesseract.image_to_string(
                    image,
                    config=self.tesseract_config.get("config", "")
                )
                
                # Analyze extracted text
                self._analyze_text(text, results)
                
            except Exception as e:
                logging.error(f"Screenshot analysis error ({screenshot_type}): {str(e)}")
    
    def _analyze_forms(self, forms: List[Dict[str, Any]], results: Dict[str, List[Dict]]) -> None:
        """Analyze HTML forms for payment-related fields"""
        payment_keywords = {
            "payment", "bank", "account", "transfer", "wallet",
            "pembayaran", "rekening", "transfer", "dompet"
        }
        
        for form in forms:
            payment_fields = []
            
            # Check form action URL
            action = form.get("action", "").lower()
            if any(kw in action for kw in payment_keywords):
                payment_fields.append({
                    "type": "form_action",
                    "value": action
                })
            
            # Check form inputs
            for input_ in form.get("inputs", []):
                input_type = input_.get("type", "")
                input_name = input_.get("name", "").lower()
                
                if any(kw in input_name for kw in payment_keywords):
                    payment_fields.append({
                        "type": input_type,
                        "name": input_name
                    })
            
            if payment_fields:
                results["forms"].append({
                    "action": action,
                    "method": form.get("method", ""),
                    "payment_fields": payment_fields
                })
    
    def _calculate_risk_score(self, results: Dict[str, List]) -> int:
        """Calculate risk score based on detected payment channels"""
        score = 0
        
        # QRIS codes are high risk
        score += len(results["qris_codes"]) * 3
        
        # Bank accounts are medium-high risk
        score += len(results["bank_accounts"]) * 2
        
        # E-wallets are medium risk
        score += len(results["ewallets"]) * 2
        
        # Phone numbers are low-medium risk
        score += len(results["phone_numbers"])
        
        # Payment forms add additional risk
        score += len(results["forms"])
        
        # Normalize score to 0-10 range
        return min(10, score)
    
    async def cleanup(self) -> None:
        """Clean up resources"""
        self.is_initialized = False