import yaml
import os
from typing import Dict, Any, List
import logging

class ConfigLoader:
    """Configuration loader for the C.A.K.R.A scanner."""
    
    def __init__(self, config_file: str = "config.yaml"):
        self.config_file = config_file
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        try:
            if not os.path.exists(self.config_file):
                logging.warning(f"Config file {self.config_file} not found, using defaults")
                return self._get_default_config()
            
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            
            # Merge with defaults to ensure all keys exist
            default_config = self._get_default_config()
            merged_config = self._deep_merge(default_config, config)
            
            logging.info(f"Configuration loaded from {self.config_file}")
            return merged_config
            
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            logging.info("Using default configuration")
            return self._get_default_config()
    
    def _deep_merge(self, base: Dict, override: Dict) -> Dict:
        """Deep merge two dictionaries."""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        return result
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            'models': {
                'text': 'qwen2:0.5b',
                'vision': 'moondream:1.8b',
                'judge': 'deepseek-r1:1.5b'
            },
            'database': {
                'filename': 'scan_results.db',
                'enable_cache': True,
                'cache_duration_hours': 1
            },
            'shadowdoor_domains': {
                'illegal_gambling': [
                    'example-gambling-site.com',
                    'fake-casino.net',
                    'illegal-betting.org'
                ],
                'pornography': [
                    'adult-content-site.com',
                    'illegal-porn.net',
                    'explicit-material.org'
                ],
                'phishing': [
                    'fake-bank-login.com',
                    'phishing-site.net',
                    'credential-theft.org'
                ],
                'malware': [
                    'malware-host.com',
                    'trojan-download.net',
                    'ransomware-site.org'
                ]
            },
            'vulnerability_patterns': {
                'outdated_software': ['wordpress', 'joomla', 'drupal'],
                'exposed_admin': ['/admin', '/wp-admin', '/administrator'],
                'weak_permissions': ['chmod 777', 'writable config'],
                'sql_injection': ['\' or 1=1', 'union select'],
                'xss_vulnerable': ['<script>', 'javascript:', 'onload='],
                'file_upload': ['upload.php', 'filemanager'],
                'default_credentials': ['admin/admin', 'root/root']
            },
            'malicious_keywords': [
                'casino', 'gambling', 'redirect', 'illegal', 'porn', 'drugs',
                'judi', 'jvdi', 'ju_di', 'toGel', 'tog3l', 't0gel',
                'slot', 'sl0t', 's|ot', 'gacor', 'g@cor', 'gac0r',
                'taruhan', 'taruh@n', 'bet', 'b3t', 'b3tting',
                'poker', 'p0ker', 'pok3r', 'kasino', 'c@sin0',
                'jackpot', 'jackp0t', 'j@ckpot', 'bola', 'b0la',
                '18+', 'dewasa', 'dewas@', 'bokep', 'b0kep', 'boqep',
                'film panas', 'film p@nas', 'seks', 's3ks', 's3x',
                'ml', 'm3sum', 'mesum', 'video dewasa', 'vidio dewasa',
                'cewek nakal', 'c3wek nakal', 'cwk nakal',
                'ABG nakal', 'ABG n@kal'
            ],
            'scanning': {
                'max_workers': 3,
                'request_timeout': 10,
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'selenium_enabled': True
            },
            'intelligence': {
                'whois_enabled': True,
                'dns_analysis_enabled': True,
                'wayback_machine_enabled': False
            },
            'web': {
                'host': '0.0.0.0',
                'port': 5000,
                'debug': True
            },
            'indonesian_domains': [
                '.id', '.go.id', '.ac.id', '.co.id', '.or.id',
                '.net.id', '.web.id', '.sch.id', '.mil.id',
                '.gov.id', '.edu', '.com', '.org', '.net'
            ]
        }
    
    def get(self, key: str, default=None):
        """Get a configuration value by key (supports dot notation)."""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def get_models(self) -> Dict[str, str]:
        """Get model configuration."""
        return self.config.get('models', {})
    
    def get_database_config(self) -> Dict[str, Any]:
        """Get database configuration."""
        return self.config.get('database', {})
    
    def get_shadowdoor_domains(self) -> Dict[str, List[str]]:
        """Get shadowdoor domains configuration."""
        return self.config.get('shadowdoor_domains', {})
    
    def get_vulnerability_patterns(self) -> Dict[str, List[str]]:
        """Get vulnerability patterns configuration."""
        return self.config.get('vulnerability_patterns', {})
    
    def get_malicious_keywords(self) -> List[str]:
        """Get malicious keywords list."""
        return self.config.get('malicious_keywords', [])
    
    def get_scanning_config(self) -> Dict[str, Any]:
        """Get scanning configuration."""
        return self.config.get('scanning', {})
    
    def get_intelligence_config(self) -> Dict[str, Any]:
        """Get intelligence gathering configuration."""
        return self.config.get('intelligence', {})
    
    def get_web_config(self) -> Dict[str, Any]:
        """Get web interface configuration."""
        return self.config.get('web', {})
    
    def get_indonesian_domains(self) -> List[str]:
        """Get Indonesian domains list."""
        return self.config.get('indonesian_domains', [])
    
    def reload_config(self) -> bool:
        """Reload configuration from file."""
        try:
            self.config = self._load_config()
            logging.info("Configuration reloaded successfully")
            return True
        except Exception as e:
            logging.error(f"Error reloading configuration: {e}")
            return False
    
    def save_config(self, new_config: Dict[str, Any] = None) -> bool:
        """Save current configuration to file."""
        try:
            config_to_save = new_config if new_config is not None else self.config
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                yaml.dump(config_to_save, f, default_flow_style=False, allow_unicode=True)
            
            if new_config is not None:
                self.config = new_config
            
            logging.info(f"Configuration saved to {self.config_file}")
            return True
            
        except Exception as e:
            logging.error(f"Error saving configuration: {e}")
            return False
    
    def update_malicious_keywords(self, new_keywords: List[str]) -> bool:
        """Update malicious keywords list and save to config."""
        try:
            current_keywords = set(self.get_malicious_keywords())
            current_keywords.update(new_keywords)
            
            self.config['malicious_keywords'] = sorted(list(current_keywords))
            return self.save_config()
            
        except Exception as e:
            logging.error(f"Error updating malicious keywords: {e}")
            return False
    
    def add_shadowdoor_domain(self, category: str, domain: str) -> bool:
        """Add a new shadowdoor domain and save to config."""
        try:
            if 'shadowdoor_domains' not in self.config:
                self.config['shadowdoor_domains'] = {}
            
            if category not in self.config['shadowdoor_domains']:
                self.config['shadowdoor_domains'][category] = []
            
            if domain not in self.config['shadowdoor_domains'][category]:
                self.config['shadowdoor_domains'][category].append(domain)
                return self.save_config()
            
            return True  # Domain already exists
            
        except Exception as e:
            logging.error(f"Error adding shadowdoor domain: {e}")
            return False
    
    def validate_config(self) -> List[str]:
        """Validate configuration and return list of issues."""
        issues = []
        
        # Check required sections
        required_sections = ['models', 'database', 'scanning', 'web']
        for section in required_sections:
            if section not in self.config:
                issues.append(f"Missing required configuration section: {section}")
        
        # Check model names
        models = self.config.get('models', {})
        required_models = ['text', 'vision', 'judge']
        for model_type in required_models:
            if model_type not in models or not models[model_type]:
                issues.append(f"Missing or empty model configuration: {model_type}")
        
        # Check database filename
        db_config = self.config.get('database', {})
        if not db_config.get('filename'):
            issues.append("Database filename not specified")
        
        # Check web configuration
        web_config = self.config.get('web', {})
        port = web_config.get('port')
        if not isinstance(port, int) or port < 1 or port > 65535:
            issues.append("Invalid web port configuration")
        
        # Check scanning configuration
        scanning_config = self.config.get('scanning', {})
        max_workers = scanning_config.get('max_workers')
        if not isinstance(max_workers, int) or max_workers < 1:
            issues.append("Invalid max_workers configuration")
        
        timeout = scanning_config.get('request_timeout')
        if not isinstance(timeout, (int, float)) or timeout < 1:
            issues.append("Invalid request_timeout configuration")
        
        return issues
