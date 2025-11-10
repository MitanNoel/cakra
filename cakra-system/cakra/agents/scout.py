"""CAKRA - Scout Agent

Handles web crawling and content gathering using Playwright with resource optimization.
"""

import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging
from urllib.parse import urljoin, urlparse

from playwright.async_api import async_playwright, Browser, Page, Response
from bs4 import BeautifulSoup
from pydantic import BaseModel

from .base import Agent

class ScoutConfig(BaseModel):
    """Configuration for Scout Agent"""
    max_depth: int = 3
    max_pages: int = 100
    timeout: int = 30000
    user_agent: str = "Mozilla/5.0 CAKRA Scanner/1.0"

class ScoutAgent(Agent):
    """Web crawler and content gatherer"""
    
    def __init__(self, config: Any):
        super().__init__(config)
        self.playwright = None
        self.browser: Optional[Browser] = None
        self.context = None
        scout_config = ScoutConfig()
        self.max_depth = scout_config.max_depth
        self.max_pages = scout_config.max_pages
        self.timeout = scout_config.timeout
        self.user_agent = scout_config.user_agent
    
    async def initialize(self) -> None:
        """Initialize Playwright browser"""
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(
            headless=True,
        )
        self.context = await self.browser.new_context(
            user_agent=self.user_agent,
            viewport={"width": 1920, "height": 1080},
            java_script_enabled=True
        )
        self.is_initialized = True
    
    async def analyze(self, data: Any) -> Dict[str, Any]:
        """Analyze a website and gather content"""
        # Extract URL from data parameter
        if isinstance(data, str):
            url = data
        elif isinstance(data, dict) and "url" in data:
            url = data["url"]
        else:
            return {
                "error": "Invalid input: expected URL string or dict with 'url' key",
                "timestamp": datetime.utcnow().isoformat()
            }
        
        # Ensure context is initialized
        if not self.context:
            return {
                "url": url,
                "error": "Browser context not initialized",
                "timestamp": datetime.utcnow().isoformat()
            }
        
        page = None
        try:
            page = await self.context.new_page()
            if not page:
                return {
                    "url": url,
                    "error": "Failed to create new page",
                    "timestamp": datetime.utcnow().isoformat()
                }
                
            # Set timeout (synchronous method)
            page.set_default_timeout(self.timeout)
            
            # Gather basic info and screenshot
            basic_info = await self._gather_basic_info(page, url)
            if basic_info.get("error"):
                return basic_info
            
            # Extract content and analyze page structure
            content_info = await self._extract_content(page)
            
            # Gather links and take screenshots
            link_info = await self._gather_links(page, url)
            screenshot_info = await self._take_screenshots(page)
            
            return {
                **basic_info,
                **content_info,
                **link_info,
                **screenshot_info,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logging.error(f"Error analyzing {url}: {str(e)}")
            return {
                "url": url,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
        finally:
            # Always close the page
            if page:
                try:
                    await page.close()
                except Exception:
                    pass  # Ignore close errors
    
    async def _gather_basic_info(self, page: Page, url: str) -> Dict[str, Any]:
        """Gather basic information about the website"""
        try:
            response = await page.goto(url, wait_until="networkidle")
            if not response:
                return {"url": url, "error": "Failed to load page"}
            
            return {
                "url": url,
                "status": response.status,
                "headers": dict(response.headers),
                "content_type": response.headers.get("content-type", ""),
                "title": await page.title(),
                "final_url": page.url,  # In case of redirects
            }
            
        except Exception as e:
            return {"url": url, "error": str(e)}
    
    async def _extract_content(self, page: Page) -> Dict[str, Any]:
        """Extract and analyze page content"""
        html = await page.content()
        soup = BeautifulSoup(html, "html.parser")
        
        # Get text content
        text_content = soup.get_text(separator=" ", strip=True)
        
        # Extract scripts
        scripts = []
        for script in soup.find_all("script"):
            if script.string:
                scripts.append(script.string)
        
        # Extract forms
        forms = []
        for form in soup.find_all("form"):
            forms.append({
                "action": form.get("action"),
                "method": form.get("method"),
                "inputs": [
                    {"type": input_.get("type"), "name": input_.get("name")}
                    for input_ in form.find_all("input")
                ]
            })
        
        return {
            "text_content": text_content,
            "scripts": scripts,
            "forms": forms,
            "meta_tags": [
                {"name": tag.get("name"), "content": tag.get("content")}
                for tag in soup.find_all("meta")
            ]
        }
    
    async def _gather_links(self, page: Page, base_url: str) -> Dict[str, Any]:
        """Gather and analyze links on the page"""
        links = await page.evaluate('''() => {
            const links = Array.from(document.links);
            return links.map(link => ({
                href: link.href,
                text: link.textContent,
                rel: link.rel
            }));
        }''')
        
        parsed_base = urlparse(base_url)
        internal_links = []
        external_links = []
        
        for link in links:
            try:
                parsed = urlparse(link["href"])
                if parsed.netloc == parsed_base.netloc:
                    internal_links.append(link)
                else:
                    external_links.append(link)
            except Exception:
                continue
        
        return {
            "internal_links": internal_links,
            "external_links": external_links
        }
    
    async def _take_screenshots(self, page: Page) -> Dict[str, Any]:
        """Take various screenshots of the page"""
        try:
            import base64
            
            # Full page screenshot
            full_screenshot = await page.screenshot(
                full_page=True,
                type="jpeg",
                quality=80
            )
            
            # Viewport screenshot
            viewport_screenshot = await page.screenshot(
                full_page=False,
                type="jpeg",
                quality=80
            )
            
            # Convert to base64 for JSON serialization
            return {
                "screenshots": {
                    "full_page": base64.b64encode(full_screenshot).decode('utf-8'),
                    "viewport": base64.b64encode(viewport_screenshot).decode('utf-8')
                }
            }
        except Exception as e:
            logging.error(f"Screenshot error: {str(e)}")
            return {"screenshots": None}
    
    async def cleanup(self) -> None:
        """Clean up browser resources"""
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
        self.is_initialized = False