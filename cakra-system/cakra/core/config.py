"""CAKRA - Configuration Management

Handles loading and validation of configuration from YAML files and environment variables.
"""

import os
from typing import Dict, Any, Optional
from pydantic import BaseModel, validator
import yaml

class DatabaseConfig(BaseModel):
    """Database configuration settings"""
    url: str = "sqlite+aiosqlite:///data/cakra.db"
    pool_size: int = 20
    max_overflow: int = 10
    echo: bool = False

class ScoutConfig(BaseModel):
    """Scout agent configuration"""
    max_depth: int = 3
    max_pages: int = 100
    timeout: int = 30000
    user_agent: str = "Mozilla/5.0 CAKRA Scanner/1.0"

class AnalystConfig(BaseModel):
    """Content analyst configuration"""
    text_model: str = "qwen2:0.5b"
    vision_model: str = "qwen2:0.5b"
    batch_size: int = 4
    max_tokens: int = 2048
    temperature: float = 0.7

class InvestigatorConfig(BaseModel):
    """Payment investigator configuration"""
    tesseract_config: str = ""
    batch_size: int = 4
    confidence_threshold: float = 0.7

class MapperConfig(BaseModel):
    """Network mapper configuration"""
    dns_timeout: int = 5
    whois_timeout: int = 10
    batch_size: int = 4

class ReporterConfig(BaseModel):
    """Report generator configuration"""
    model: str = "qwen2:0.5b"
    max_tokens: int = 2048
    temperature: float = 0.7
    batch_size: int = 1

class AIModels(BaseModel):
    """AI model and agent configurations"""
    scout: ScoutConfig = ScoutConfig()
    analyst: AnalystConfig = AnalystConfig()
    investigator: InvestigatorConfig = InvestigatorConfig()
    mapper: MapperConfig = MapperConfig()
    reporter: ReporterConfig = ReporterConfig()

class ResourceLimits(BaseModel):
    """System resource limits"""
    max_processes: int = 4  # Number of CPU cores
    max_memory_gb: int = 16
    crawler_threads: int = 10
    analysis_batch_size: int = 5

class ApiConfig(BaseModel):
    """API configuration"""
    host: str = "0.0.0.0"
    port: int = 5000
    workers: int = 4
    log_level: str = "info"
    enable_docs: bool = True

class Config(BaseModel):
    """Main configuration class"""
    database: DatabaseConfig = DatabaseConfig()
    models: AIModels = AIModels()
    resources: ResourceLimits = ResourceLimits()
    api: ApiConfig = ApiConfig()
    
    # Detection patterns
    malicious_keywords: list[str] = []
    shadowdoor_domains: Dict[str, list[str]] = {}
    vulnerability_patterns: Dict[str, list[str]] = {}

class ConfigLoader:
    """Configuration loader with environment variable support"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or os.getenv("CAKRA_CONFIG", "config/config.yaml")
        self.config = self._load_config()
    
    def _load_config(self) -> Config:
        """Load configuration from YAML file and environment variables"""
        # Load from file
        if os.path.exists(self.config_path):
            with open(self.config_path) as f:
                config_dict = yaml.safe_load(f)
        else:
            config_dict = {}
        
        # Override with environment variables
        env_prefix = "CAKRA_"
        for key, value in os.environ.items():
            if key.startswith(env_prefix):
                config_key = key[len(env_prefix):].lower()
                nested_keys = config_key.split("_")
                
                current = config_dict
                for k in nested_keys[:-1]:
                    current = current.setdefault(k, {})
                current[nested_keys[-1]] = value
        
        return Config(**config_dict)
    
    def get_config(self) -> Config:
        """Get the loaded configuration"""
        return self.config