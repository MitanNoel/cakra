import ollama
import requests
from bs4 import BeautifulSoup
from flask import Flask, request, render_template_string, jsonify, send_file
from flask_socketio import SocketIO, emit
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import threading
import re
import time
import os
import socket
import ssl
import csv
import io
import logging
from datetime import datetime

# Import our new modules
from database import ScanDatabase
from intelligence import IntelligenceGatherer
from config_loader import ConfigLoader

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

# Initialize configuration
config = ConfigLoader()
db = ScanDatabase(config.get_database_config()['filename'])
intelligence = IntelligenceGatherer()

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
socketio = SocketIO(app)

@socketio.on('connect')
def handle_connect():
    pass

@socketio.on('request_initial')
def handle_request_initial():
    global scanned_count, potential_count, dangerous_count, scan_results, total_sites, is_scanning, total_scanning_sites
    
    # Initialize counters if not already done
    if 'scanned_count' not in globals():
        scanned_count = 0
        potential_count = 0
        dangerous_count = 0
        total_sites = 0
        total_scanning_sites = 0
    
    # Get statistics from database
    stats = db.get_statistics()
    
    # Get all results to properly count
    all_results = db.query_results(limit=1000)
    
    # Count properly:
    # - Found: Total unique sites discovered (all entries in database)
    # - Scanned: Sites with completed analysis (both text and vision analysis done)
    found_count = len(all_results)  # Total sites discovered
    
    # A site is "scanned" if it has both text_result and vision_results, and judgment is not "Queued"
    completed_count = 0
    for result in all_results:
        has_text = result.get('text_result') and result.get('text_result').strip()
        has_vision = result.get('vision_results') and len(result.get('vision_results', [])) > 0
        is_not_queued = result.get('judgment') and result.get('judgment') != 'Queued'
        
        if has_text and has_vision and is_not_queued:
            completed_count += 1
    
    # Use database stats for threat classification
    potential_count = stats.get('potential_count', 0)
    dangerous_count = stats.get('dangerous_count', 0)
    
    # Get recent results for display
    recent_results = db.query_results(limit=100)
    
    socketio.emit('initial_state', {
        'scanned': completed_count,  # Only fully analyzed sites
        'found': found_count,        # Total discovered sites
        'potential': potential_count,
        'dangerous': dangerous_count,
        'results': recent_results,
        'total_sites': found_count
    })
    socketio.emit('total_sites', found_count)
    socketio.emit('scan_status', {'scanning': is_scanning})

# Load configuration values
OLLAMA_MODELS = config.get_models()
SHADOWDOOR_DOMAINS = config.get_shadowdoor_domains()
VULNERABILITY_PATTERNS = config.get_vulnerability_patterns()
MALICIOUS_KEYWORDS = set(config.get_malicious_keywords())

def detect_anti_crawler(html_content, js_scripts):
    """Detect common anti-crawler techniques in HTML and JS."""
    indicators = []
    
    # Check HTML for anti-crawler patterns
    if 'navigator.webdriver' in html_content:
        indicators.append('Checks for webdriver (bot detection)')
    
    if re.search(r'<script[^>]*>.*eval\(.*\)</script>', html_content, re.DOTALL):
        indicators.append('Uses eval() for obfuscation')
    
    if 'captcha' in html_content.lower() or 'recaptcha' in html_content.lower():
        indicators.append('Contains CAPTCHA elements')
    
    if 'window.location.href' in html_content and 'bot' in html_content.lower():
        indicators.append('Redirects based on bot detection')
    
    # Check JS scripts for obfuscation
    for script in js_scripts:
        if len(script) > 1000 and script.count(';') < 10:  # Likely minified/obfuscated
            indicators.append('Contains obfuscated JavaScript')
        if 'setTimeout' in script and 'location' in script:
            indicators.append('Uses delayed redirects')
    
    return indicators
scan_results = []
scan_thread = None
stop_scan = False
is_scanning = False
current_scanning = []

# Remove old file-based variables
# RESULTS_FILE = 'scan_results.json'
# CACHE_FILE = 'scan_cache.json'
# scan_cache = {}

def load_scan_results():
    """Load scan results from database (no longer needed - handled by database class)."""
    pass

def save_scan_results():
    """Save scan results to database (no longer needed - handled by database class)."""
    pass

def emit_progress():
    global scanned_count, total_scanning_sites, start_time, current_scanning
    if total_scanning_sites > 0:
        # Use initial scanning count for progress, not the dynamic total_sites
        percentage = (scanned_count / total_scanning_sites) * 100
        elapsed = time.time() - start_time
        if scanned_count > 0:
            avg_time = elapsed / scanned_count
            remaining = total_scanning_sites - scanned_count
            eta = avg_time * remaining
        else:
            eta = 0
        socketio.emit('progress', {
            'percentage': round(percentage, 2),
            'eta': round(eta, 2),
            'current_scanning': current_scanning.copy(),
            'completed': scanned_count,
            'total': total_scanning_sites
        })

def google_dork_search(keywords, domains):
    """Perform web search using DuckDuckGo for unlimited free results."""
    try:
        from ddgs import DDGS
    except ImportError:
        print("ddgs not installed, using mock")
        mock_urls = []
        for domain in domains:
            for kw in keywords[:10]:
                for i in range(50):
                    mock_urls.append(f'https://sub{i}{domain}')
        return mock_urls[:500]
    
    urls = set()
    with DDGS() as ddgs:
        for domain in domains:
            for keyword in keywords[:10]:
                query = f"site:{domain} {keyword}"
                try:
                    results = list(ddgs.text(query, max_results=50))
                    for result in results:
                        url = result.get('href', '')
                        if url:
                            urls.add(url)
                except Exception as e:
                    print(f"DuckDuckGo error: {str(e)}")
    
    return list(urls)

def clean_response(response):
    response = re.sub(r'<think>.*?</think>', '', response, flags=re.DOTALL)
    response = response.strip()
    if not response:
        response = "Safe website - no malicious content detected"
    return response

def detect_shadowdoor_links(html_content, url):
    """Detect links to known illegal/malicious domains (shadowdoor detection)."""
    shadowdoor_links = []
    
    # Extract all links from the page
    soup = BeautifulSoup(html_content, 'html.parser')
    links = soup.find_all('a', href=True)
    
    for link in links:
        href = link['href'].lower()
        for category, domains in SHADOWDOOR_DOMAINS.items():
            for domain in domains:
                if domain in href:
                    shadowdoor_links.append({
                        'url': link['href'],
                        'category': category,
                        'anchor_text': link.get_text().strip(),
                        'source_url': url
                    })
    
    return shadowdoor_links

def analyze_vulnerabilities(html_content, server_info, url):
    """Analyze website for common vulnerabilities that could lead to compromise."""
    vulnerabilities = []
    
    # Check server info for outdated software
    server = server_info.get('server', '').lower()
    for vuln_type, patterns in VULNERABILITY_PATTERNS.items():
        if vuln_type == 'outdated_software':
            for pattern in patterns:
                if pattern in server:
                    vulnerabilities.append({
                        'type': 'outdated_software',
                        'severity': 'high',
                        'description': f'Potentially outdated {pattern} installation detected',
                        'recommendation': f'Update {pattern} to latest version and apply security patches'
                    })
    
    # Check HTML for vulnerability indicators
    html_lower = html_content.lower()
    for vuln_type, patterns in VULNERABILITY_PATTERNS.items():
        if vuln_type != 'outdated_software':
            for pattern in patterns:
                if pattern in html_lower:
                    severity = 'critical' if vuln_type in ['sql_injection', 'xss_vulnerable'] else 'medium'
                    vulnerabilities.append({
                        'type': vuln_type,
                        'severity': severity,
                        'description': f'Potential {vuln_type.replace("_", " ")} vulnerability detected',
                        'recommendation': get_vulnerability_recommendation(vuln_type)
                    })
    
    # Check for weak SSL
    ssl_info = server_info.get('ssl_info', {})
    if ssl_info.get('valid') == False:
        vulnerabilities.append({
            'type': 'ssl_weakness',
            'severity': 'medium',
            'description': 'SSL certificate issues detected',
            'recommendation': 'Install valid SSL certificate and ensure proper HTTPS configuration'
        })
    
    return vulnerabilities

def get_vulnerability_recommendation(vuln_type):
    """Get specific recommendations for different vulnerability types."""
    recommendations = {
        'exposed_admin': 'Restrict access to admin panels using .htaccess or firewall rules',
        'weak_permissions': 'Set proper file permissions (755 for directories, 644 for files)',
        'sql_injection': 'Use prepared statements and input validation',
        'xss_vulnerable': 'Implement proper output encoding and Content Security Policy',
        'file_upload': 'Validate file types, restrict upload directories, and scan uploaded files',
        'default_credentials': 'Change all default passwords and use strong, unique credentials'
    }
    return recommendations.get(vuln_type, 'Consult security professional for remediation')

def detect_anti_crawler(html_content, js_scripts):
    """Detect common anti-crawler techniques in HTML and JS."""
    indicators = []
    
    # Check HTML for anti-crawler patterns
    if 'navigator.webdriver' in html_content:
        indicators.append('Checks for webdriver (bot detection)')
    
    if re.search(r'<script[^>]*>.*eval\(.*\)</script>', html_content, re.DOTALL):
        indicators.append('Uses eval() for obfuscation')
    
    if 'captcha' in html_content.lower() or 'recaptcha' in html_content.lower():
        indicators.append('Contains CAPTCHA elements')
    
    if 'window.location.href' in html_content and 'bot' in html_content.lower():
        indicators.append('Redirects based on bot detection')
    
    # Check JS scripts for obfuscation
    for script in js_scripts:
        if len(script) > 1000 and script.count(';') < 10:  # Likely minified/obfuscated
            indicators.append('Contains obfuscated JavaScript')
        if 'setTimeout' in script and 'location' in script:
            indicators.append('Uses delayed redirects')
    
    return indicators

def fetch_with_selenium(url):
    """Fetch page content using Selenium for JS-heavy sites."""
    if not SELENIUM_AVAILABLE:
        return None
    
    import tempfile
    import os
    import time
    import uuid
    
    # Create a unique temporary directory for this session
    session_id = str(uuid.uuid4())[:8]
    temp_dir = tempfile.mkdtemp(prefix=f'selenium_{session_id}_')
    
    options = Options()
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--disable-gpu')
    options.add_argument('--window-size=1280,720')  # Reduced resolution for faster rendering
    options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
    options.add_argument(f'--user-data-dir={temp_dir}')
    options.add_argument('--disable-extensions')
    options.add_argument('--disable-plugins')
    options.add_argument('--disable-background-timer-throttling')  # Faster processing
    options.add_argument('--disable-backgrounding-occluded-windows')
    options.add_argument('--disable-renderer-backgrounding')
    options.add_argument('--disable-features=VizDisplayCompositor')  # Faster rendering
    # Removed --disable-images to allow image analysis
    
    driver = None
    try:
        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(5)  # Reduce timeout from default 10s to 5s
        driver.get(url)
        
        # Wait for page to load with reduced timeout
        WebDriverWait(driver, 5).until(  # Reduced from 10s to 5s
            lambda d: d.execute_script('return document.readyState') == 'complete'
        )
        
        # Get rendered HTML
        html = driver.page_source
        soup = BeautifulSoup(html, 'html.parser')
        
        text_content = soup.get_text()
        
        # Extract images with better URL handling
        images = []
        from urllib.parse import urljoin
        for img in soup.find_all('img'):
            if 'src' in img.attrs:
                img_src = img['src']
                # Convert relative URLs to absolute URLs
                if img_src.startswith('http'):
                    images.append(img_src)
                elif img_src.startswith('/') or img_src.startswith('./'):
                    absolute_url = urljoin(url, img_src)
                    images.append(absolute_url)
        
        js_scripts = [script.get_text() for script in soup.find_all('script') if script.get_text()]
        
        return {
            'text_content': text_content,
            'images': images[:10],  # Limit to first 10 images
            'js_scripts': js_scripts,
            'html': html
        }
    except Exception as e:
        print(f"Selenium error: {e}")
        return None
    finally:
        if driver:
            driver.quit()
        # Clean up temporary directory
        try:
            import shutil
            shutil.rmtree(temp_dir)
        except:
            pass

def analyze_text(content, model):
    prompt = f"Analyze this webpage text for malicious or illegal keywords like {', '.join(MALICIOUS_KEYWORDS)}. Provide a brief summary of findings. Also, extract any new keywords related to pornography or gambling found in the text."
    try:
        response = ollama.generate(model=model, prompt=prompt + '\n\n' + content[:2000])
        cleaned = clean_response(response['response'])
        new_keywords = []
        if 'new keywords:' in cleaned.lower():
            parts = cleaned.lower().split('new keywords:')
            if len(parts) > 1:
                new_part = parts[1].split('\n')[0]
                new_keywords = [word.strip() for word in new_part.split(',') if word.strip()]
        return cleaned, new_keywords
    except Exception as e:
        return f"Error: {str(e)}", []

def analyze_images(images, model):
    """Analyze images for security threats and malicious content."""
    if not images:
        return {"results": ["No images found for analysis"], "analyzed_images": []}
    
    results = []
    analyzed_images = []
    
    # Check if vision model is available
    try:
        # Test if the model exists
        test_response = ollama.list()
        
        # Handle Ollama ListResponse object
        available_models = []
        if hasattr(test_response, 'models'):
            for m in test_response.models:
                if hasattr(m, 'model'):
                    available_models.append(m.model)
                elif hasattr(m, 'name'):
                    available_models.append(m.name)
                else:
                    available_models.append(str(m))
        
        if model not in available_models:
            return {"results": [f"Vision model '{model}' not available. Available models: {', '.join(available_models)}"], "analyzed_images": []}
    except Exception as e:
        # Don't fail vision analysis completely, just log the error and continue
        print(f"Warning: Could not check model availability: {str(e)}")
        # Continue with analysis anyway
    
    for i, img_url in enumerate(images[:3]):  # Reduced from 5 to 3 images for faster analysis
        try:
            print(f"Analyzing image {i+1}/{min(3, len(images))}: {img_url}")
            
            # Download image first with reduced timeout
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(img_url, stream=True, timeout=8, headers=headers)  # Reduced from 15s to 8s
            response.raise_for_status()
            
            # Check if it's actually an image
            content_type = response.headers.get('content-type', '')
            if not content_type.startswith('image/'):
                results.append(f"Skipped non-image content: {img_url}")
                continue
            
            # Save temporarily
            import tempfile
            import base64
            
            with tempfile.NamedTemporaryFile(delete=False, suffix='.jpg') as tmp_file:
                for chunk in response.iter_content(chunk_size=8192):
                    tmp_file.write(chunk)
                tmp_path = tmp_file.name
            
            try:
                # Read image as base64 for Ollama
                with open(tmp_path, 'rb') as img_file:
                    img_data = base64.b64encode(img_file.read()).decode('utf-8')
                
                prompt = """Analyze this image for security concerns. Look for:
- Gambling symbols, casino elements, betting interfaces
- Adult or inappropriate content
- Phishing attempts or fake login forms
- Malicious download buttons or suspicious links
- Illegal content indicators
- Scam or fraud indicators
- Suspicious visual elements that could deceive users

Provide a brief security assessment."""
                
                print(f"Sending image to Ollama model: {model}")
                response = ollama.generate(model=model, prompt=prompt, images=[img_data])
                analysis_result = response['response']
                results.append(f"Image {i+1}: {analysis_result}")
                analyzed_images.append({"url": img_url, "analysis": analysis_result})
                print(f"Vision analysis complete for image {i+1}")
                
            finally:
                # Clean up temp file
                import os
                try:
                    os.unlink(tmp_path)
                except:
                    pass
                    
        except requests.exceptions.RequestException as e:
            results.append(f"Failed to download image {i+1} ({img_url}): {str(e)}")
        except Exception as e:
            results.append(f"Error analyzing image {i+1} ({img_url}): {str(e)}")
    
    return {
        "results": results if results else ["No images could be analyzed"],
        "analyzed_images": analyzed_images
    }

def judge_evidence(text_result, vision_results, url, server_info, shadowdoor_links, vulnerabilities, model):
    # Handle vision_results whether it's the old format (list) or new format (dict)
    if isinstance(vision_results, dict):
        vision_text = '; '.join(vision_results.get('results', []))
    else:
        vision_text = '; '.join(vision_results) if vision_results else ''
    
    evidence = f"Text: {text_result}\nVision: {vision_text}\nServer Info: {json.dumps(server_info)}\nShadowdoor Links: {json.dumps(shadowdoor_links)}\nVulnerabilities: {json.dumps(vulnerabilities)}"
    prompt = f"Based on evidence from text, vision analysis, server information, shadowdoor detection, and vulnerability analysis of {url}, provide a structured judgment:\n- Confidence Score (0-100, where 0 is very safe and 100 is very dangerous)\n- Detailed Result (malicious/safe)\n- Website Weaknesses (e.g., outdated software, missing security headers like HTTPS, HSTS, CSP, X-Frame-Options)\n- Security Vulnerabilities (potential XSS, SQL injection, CSRF indicators)\n- Shadowdoor/Defacement Detection (links to illegal content, malicious domains)\n- Domain/IP Address: {server_info.get('ip_address', 'Unknown')}\n- Server Version: {server_info.get('server', 'Unknown')}\n- Content Analysis: Check for malicious scripts, phishing elements, or illegal content\n- Recommendations (only for detailed view)"
    try:
        response = ollama.generate(model=model, prompt=prompt + '\n\n' + evidence)
        full_response = clean_response(response['response'])
        
        # Extract confidence score
        confidence = None
        lines = full_response.split('\n')
        for line in lines:
            if 'confidence score' in line.lower():
                # Extract number from the line
                import re
                match = re.search(r'\b(\d{1,3})\b', line)
                if match:
                    confidence = int(match.group(1))
                    if 0 <= confidence <= 100:
                        break
        
        return full_response, confidence
    except Exception as e:
        return f"Error: {str(e)}", None

def scan_site(url):
    """Scan a single site: fetch content, analyze with AI, return analysis results."""
    current_scanning.append(url)
    emit_progress()
    
    # Emit analyzing status
    emit_data = {
        'url': url, 
        'judgment': 'Analyzing in Progress', 
        'text_result': 'Fetching and analyzing content...', 
        'vision_results': ['Analyzing images...'],
        'server_info': {}
    }
    socketio.emit('scan_update', emit_data)
    
    # Check database cache first
    cached_result = db.get_scan_result(url)
    if cached_result and config.get_database_config()['enable_cache']:
        cache_time = datetime.fromisoformat(cached_result['updated_at'])
        cache_duration = config.get_database_config()['cache_duration_hours']
        if (datetime.now() - cache_time).total_seconds() < (cache_duration * 3600):
            cached_result['cached'] = True
            current_scanning.remove(url) if url in current_scanning else None
            return cached_result
    
    try:
        start_time_req = time.time()
        response = requests.get(url, timeout=config.get_scanning_config()['request_timeout'], 
                              headers={'User-Agent': config.get_scanning_config()['user_agent']})
        response_time = time.time() - start_time_req
        
        # Check for redirects
        if response.url != url:
            # Emit new URL for scanning
            new_url = response.url
            if new_url not in current_scanning:
                emit_data = {
                    'url': new_url, 
                    'judgment': 'Queued', 
                    'text_result': 'Queued, waiting for analyzed', 
                    'vision_results': ['Queued, waiting for analyzed'],
                    'server_info': {}
                }
                socketio.emit('scan_update', emit_data)
                current_scanning.append(new_url)
                # Note: To scan it, user can restart scan or add manually
        
        soup = BeautifulSoup(response.text, 'html.parser')
        text_content = soup.get_text()
        
        # Extract images with better URL handling
        images = []
        from urllib.parse import urljoin
        for img in soup.find_all('img'):
            if 'src' in img.attrs:
                img_src = img['src']
                # Convert relative URLs to absolute URLs
                if img_src.startswith('http'):
                    images.append(img_src)
                elif img_src.startswith('/') or img_src.startswith('./'):
                    absolute_url = urljoin(url, img_src)
                    images.append(absolute_url)
        
        images = images[:10]  # Limit to first 10 images
        js_scripts = [script.get_text() for script in soup.find_all('script') if script.get_text()]
        
        # Detect anti-crawler techniques
        anti_crawler_indicators = detect_anti_crawler(response.text, js_scripts)
        
        # Smart Selenium usage - only when really needed
        use_selenium = False
        content_suspicious = len(text_content.strip()) < 100
        has_heavy_js = len(js_scripts) > 5 or any(len(script) > 5000 for script in js_scripts)
        
        # Only use Selenium if content is suspicious AND has heavy JS (likely needs rendering)
        if content_suspicious and has_heavy_js and anti_crawler_indicators:
            selenium_data = fetch_with_selenium(url)
            if selenium_data:
                text_content = selenium_data['text_content']
                images = selenium_data['images']
                js_scripts = selenium_data['js_scripts']
                use_selenium = True
        
        # Get server information
        server_info = {
            'server': response.headers.get('Server', 'Unknown'),
            'ip_address': socket.gethostbyname(response.url.replace('https://', '').replace('http://', '').split('/')[0]),
            'status_code': response.status_code,
            'content_type': response.headers.get('Content-Type', 'Unknown'),
            'last_modified': response.headers.get('Last-Modified', 'Unknown'),
            'content_length': response.headers.get('Content-Length', 'Unknown'),
            'final_url': response.url,
            'response_time': round(response_time, 2),
            'ssl_info': {},
            'anti_crawler_indicators': anti_crawler_indicators,
            'used_selenium': use_selenium
        }
        
        # SSL Certificate Analysis
        if response.url.startswith('https://'):
            try:
                hostname = response.url.replace('https://', '').split('/')[0]
                context = ssl.create_default_context()
                with socket.create_connection((hostname, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        server_info['ssl_info'] = {
                            'issuer': dict(x[0] for x in cert.get('issuer', [])),
                            'subject': dict(x[0] for x in cert.get('subject', [])),
                            'version': cert.get('version'),
                            'notBefore': cert.get('notBefore'),
                            'notAfter': cert.get('notAfter'),
                            'serialNumber': cert.get('serialNumber'),
                            'valid': True
                        }
            except Exception as e:
                server_info['ssl_info'] = {'valid': False, 'error': str(e)}
        
        # Detect shadowdoor links
        shadowdoor_links = detect_shadowdoor_links(response.text, url)
        
        # Analyze vulnerabilities
        vulnerabilities = analyze_vulnerabilities(response.text, server_info, url)
        
        # Intelligence gathering
        domain_intelligence = {}
        if config.get_intelligence_config()['whois_enabled'] or config.get_intelligence_config()['dns_analysis_enabled']:
            try:
                domain_analysis = intelligence.comprehensive_domain_analysis(url)
                domain_intelligence = {
                    'domain': domain_analysis['domain'],
                    'whois_data': domain_analysis['whois'],
                    'dns_data': domain_analysis['dns'],
                    'geolocation_data': domain_analysis['geolocation'],
                    'risk_score': domain_analysis['overall_risk_score'],
                    'risk_factors': domain_analysis['risk_factors'],
                    'recommendations': domain_analysis['recommendations']
                }
                
                # Save domain intelligence to database
                if domain_analysis['whois'].get('success'):
                    whois_data = domain_analysis['whois']['data']
                    db.save_domain_intelligence(
                        domain_analysis['domain'],
                        whois_data,
                        domain_analysis['dns']['data'] if domain_analysis['dns'].get('success') else {},
                        whois_data.get('creation_date'),
                        whois_data.get('registrar'),
                        whois_data.get('domain_age_days')
                    )
                
            except Exception as e:
                logging.error(f"Intelligence gathering failed for {url}: {e}")
        
        # AI Analysis
        text_result, new_keywords = analyze_text(text_content, OLLAMA_MODELS['text'])
        vision_analysis = analyze_images(images, OLLAMA_MODELS['vision'])
        vision_results = vision_analysis.get("results", []) if isinstance(vision_analysis, dict) else vision_analysis
        analyzed_images = vision_analysis.get("analyzed_images", []) if isinstance(vision_analysis, dict) else []
        
        result = {
            'url': url, 
            'text_result': text_result, 
            'vision_results': vision_results, 
            'analyzed_images': analyzed_images,
            'new_keywords': new_keywords,
            'server_info': server_info,
            'shadowdoor_links': shadowdoor_links,
            'vulnerabilities': vulnerabilities,
            'domain_intelligence': domain_intelligence
        }
        
        # Save to database
        db.save_scan_result(result)
        
        return result
    except Exception as e:
        result = {'url': url, 'error': str(e)}
        # Save error result to database
        db.save_scan_result(result)
        return result
    finally:
        current_scanning.remove(url) if url in current_scanning else None

def parallel_scan(sites, max_workers=8):  # Increased from 3 to 8 for faster processing
    """Scan multiple sites in parallel for analysis, then judge sequentially."""
    global scanned_count, potential_count, dangerous_count, scan_results, current_scanning, start_time, stop_scan, is_scanning, total_sites, total_scanning_sites
    analysis_results = []
    start_time = time.time()
    
    # Remove duplicates from sites
    unique_sites = list(set(sites))
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Emit queued status for all sites
        for site in unique_sites:
            emit_data = {
                'url': site, 
                'judgment': 'Queued', 
                'text_result': 'Queued, waiting for analyzed', 
                'vision_results': ['Queued, waiting for analyzed'],
                'server_info': {}
            }
            socketio.emit('scan_update', emit_data)
        
        futures = {executor.submit(scan_site, site): site for site in unique_sites}
        while futures:
            for future in as_completed(futures):
                if stop_scan:
                    break
                site = futures[future]
                current_scanning.remove(site) if site in current_scanning else None
                result = future.result()
                analysis_results.append(result)
                scanned_count += 1
                
                # Check for redirects in result
                if 'server_info' in result and result.get('server_info', {}).get('final_url') and result['server_info']['final_url'] != result['url']:
                    new_url = result['server_info']['final_url']
                    if new_url not in unique_sites and new_url not in [futures[f] for f in futures]:
                        unique_sites.append(new_url)
                        futures[executor.submit(scan_site, new_url)] = new_url
                        global total_sites
                        total_sites += 1
                        socketio.emit('total_sites', total_sites)
                        # Emit queued for new URL
                        emit_data = {
                            'url': new_url, 
                            'judgment': 'Queued', 
                            'text_result': 'Queued, waiting for analyzed', 
                            'vision_results': ['Queued, waiting for analyzed'],
                            'server_info': {}
                        }
                        socketio.emit('scan_update', emit_data)
                
                # Emit partial update (analysis done, pending judgment)
                if 'error' in result:
                    emit_data = {
                        'url': result['url'], 
                        'judgment': 'Error', 
                        'text_result': 'Analysis failed due to error', 
                        'vision_results': [], 
                        'error': result['error'],
                        'server_info': {}
                    }
                else:
                    emit_data = {
                        'url': result['url'], 
                        'judgment': 'Judging in Progress', 
                        'text_result': result['text_result'], 
                        'vision_results': result['vision_results'],
                        'server_info': result.get('server_info', {})
                    }
                socketio.emit('scan_update', emit_data)
                emit_progress()
                del futures[future]  # Remove completed future
                break  # Process one at a time to allow adding new ones
    
    # Now judge sequentially
    for result in analysis_results:
        if stop_scan:
            break
        if 'error' not in result:
            final_judgment, confidence = judge_evidence(
                result['text_result'], 
                result['vision_results'], 
                result['url'], 
                result.get('server_info', {}),
                result.get('shadowdoor_links', []),
                result.get('vulnerabilities', []),
                OLLAMA_MODELS['judge']
            )
            if not final_judgment or final_judgment.strip() == '':
                final_judgment = "Safe website - no malicious content detected"
                confidence = 0
            
            # Update result with judgment and confidence
            result['judgment'] = final_judgment
            result['confidence'] = confidence
            
            # Parse judgment for counters
            judgment = final_judgment.lower()
            if 'malicious' in judgment or 'dangerous' in judgment:
                dangerous_count += 1
                # Learn new keywords
                new_keywords = result.get('new_keywords', [])
                for kw in new_keywords:
                    if kw not in MALICIOUS_KEYWORDS:
                        MALICIOUS_KEYWORDS.add(kw)
            elif 'potential' in judgment or 'suspicious' in judgment:
                potential_count += 1
            
            # Increment scanned count for each completed scan
            scanned_count += 1
            
            # Emit dashboard counter updates in real-time
            socketio.emit('dashboard_update', {
                'scanned': scanned_count,
                'potential': potential_count, 
                'dangerous': dangerous_count,
                'found': total_sites
            })
            
            # Emit final update
            emit_data = {
                'url': result['url'], 
                'judgment': final_judgment, 
                'confidence': confidence, 
                'text_result': result['text_result'], 
                'vision_results': result['vision_results'],
                'server_info': result.get('server_info', {}),
                'shadowdoor_links': result.get('shadowdoor_links', []),
                'vulnerabilities': result.get('vulnerabilities', [])
            }
            socketio.emit('scan_update', emit_data)
            emit_progress()  # Emit progress after each completion
    
    scan_results.extend(analysis_results)
    # No need to save results here - they're saved individually in scan_site
    # save_scan_results()  # Save results after scan completes
    is_scanning = False
    socketio.emit('scan_status', {'scanning': False})

@app.route('/')
def home():
    html = r"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>C.A.K.R.A. Security Scanner</title>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.5/socket.io.js"></script>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                color: #333;
            }
            .header {
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(10px);
                padding: 1.5rem 2rem;
                box-shadow: 0 2px 20px rgba(0,0,0,0.1);
                border-bottom: 1px solid rgba(255,255,255,0.2);
                text-align: center;
            }
            .header h1 {
                color: #2c3e50;
                font-size: 2.2rem;
                font-weight: 600;
                margin: 0;
            }
            .header .subtitle {
                color: #7f8c8d;
                font-size: 1rem;
                margin-top: 0.5rem;
                font-weight: 400;
            }
            .system-note {
                background: rgba(255, 193, 7, 0.1);
                border: 1px solid rgba(255, 193, 7, 0.3);
                border-radius: 8px;
                padding: 0.75rem 1rem;
                margin-top: 1rem;
                color: #856404;
                font-size: 0.9rem;
                display: ${SELENIUM_AVAILABLE ? 'none' : 'block'};
            }
            .container {
                max-width: 1400px;
                margin: 2rem auto;
                padding: 0 2rem;
                display: grid;
                gap: 2rem;
                grid-template-columns: 1fr;
            }
            /* Dashboard Components */
            .dashboard-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 1.5rem;
                margin-bottom: 2rem;
            }
            .card {
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(10px);
                border-radius: 12px;
                padding: 1.5rem;
                box-shadow: 0 8px 32px rgba(0,0,0,0.1);
                border: 1px solid rgba(255,255,255,0.2);
                transition: transform 0.2s ease, box-shadow 0.2s ease;
            }
            .card:hover {
                transform: translateY(-2px);
                box-shadow: 0 12px 40px rgba(0,0,0,0.15);
            }
            .counter-card {
                text-align: center;
                position: relative;
                overflow: hidden;
            }
            .counter-card::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 4px;
                background: var(--accent-color);
            }
            .counter-card.scanned { --accent-color: #3498db; }
            .counter-card.potential { --accent-color: #f39c12; }
            .counter-card.dangerous { --accent-color: #e74c3c; }
            .counter-card.found { --accent-color: #9b59b6; }
            .counter-number {
                font-size: 2.5rem;
                font-weight: bold;
                color: var(--accent-color);
                margin-bottom: 0.5rem;
            }
            .counter-label {
                color: #7f8c8d;
                font-weight: 500;
                text-transform: uppercase;
                font-size: 0.85rem;
                letter-spacing: 1px;
            }
            /* Form Styles */
            .control-panel {
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(10px);
                border-radius: 12px;
                padding: 2rem;
                box-shadow: 0 8px 32px rgba(0,0,0,0.1);
                border: 1px solid rgba(255,255,255,0.2);
            }
            .control-panel h3 {
                color: #2c3e50;
                margin-bottom: 1.5rem;
                font-size: 1.3rem;
                font-weight: 600;
            }
            textarea {
                width: 100%;
                min-height: 120px;
                padding: 1rem;
                border: 2px solid #ecf0f1;
                border-radius: 8px;
                font-family: 'Consolas', monospace;
                font-size: 0.9rem;
                resize: vertical;
                transition: border-color 0.3s ease;
                background: #fafbfc;
            }
            textarea:focus {
                outline: none;
                border-color: #3498db;
                background: white;
            }
            .form-section {
                margin: 1.5rem 0;
            }
            .form-section label {
                display: block;
                margin-bottom: 0.75rem;
                font-weight: 600;
                color: #2c3e50;
            }
            .domain-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
                gap: 0.75rem;
                margin-top: 0.75rem;
            }
            .domain-checkbox {
                display: flex;
                align-items: center;
                padding: 0.5rem;
                background: #f8f9fa;
                border-radius: 6px;
                transition: background-color 0.2s ease;
                cursor: pointer;
            }
            .domain-checkbox:hover {
                background: #e9ecef;
            }
            .domain-checkbox input {
                margin-right: 0.5rem;
                transform: scale(1.1);
            }
            .button-group {
                display: flex;
                gap: 1rem;
                margin-top: 2rem;
                flex-wrap: wrap;
            }
            .btn {
                padding: 0.75rem 1.5rem;
                border: none;
                border-radius: 8px;
                font-weight: 600;
                font-size: 0.9rem;
                cursor: pointer;
                transition: all 0.3s ease;
                text-decoration: none;
                display: inline-flex;
                align-items: center;
                gap: 0.5rem;
            }
            .btn-primary {
                background: linear-gradient(135deg, #3498db, #2980b9);
                color: white;
            }
            .btn-primary:hover {
                background: linear-gradient(135deg, #2980b9, #21618c);
                transform: translateY(-1px);
                box-shadow: 0 4px 12px rgba(52, 152, 219, 0.3);
            }
            .btn-secondary {
                background: linear-gradient(135deg, #95a5a6, #7f8c8d);
                color: white;
            }
            .btn-secondary:hover {
                background: linear-gradient(135deg, #7f8c8d, #6c7b7d);
                transform: translateY(-1px);
                box-shadow: 0 4px 12px rgba(149, 165, 166, 0.3);
            }
            .btn-accent {
                background: linear-gradient(135deg, #9b59b6, #8e44ad);
                color: white;
            }
            .btn-accent:hover {
                background: linear-gradient(135deg, #8e44ad, #7d3c98);
                transform: translateY(-1px);
                box-shadow: 0 4px 12px rgba(155, 89, 182, 0.3);
            }
            /* Progress Styles */
            .progress-section {
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(10px);
                border-radius: 12px;
                padding: 2rem;
                box-shadow: 0 8px 32px rgba(0,0,0,0.1);
                border: 1px solid rgba(255,255,255,0.2);
                margin-bottom: 2rem;
            }
            .progress-bar-container {
                background: #ecf0f1;
                border-radius: 10px;
                height: 12px;
                overflow: hidden;
                margin: 1rem 0;
            }
            .progress-bar {
                height: 100%;
                background: linear-gradient(90deg, #3498db, #2ecc71);
                border-radius: 10px;
                transition: width 0.5s ease;
                position: relative;
            }
            .progress-bar::after {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
                animation: shimmer 2s infinite;
            }
            @keyframes shimmer {
                0% { transform: translateX(-100%); }
                100% { transform: translateX(100%); }
            }
            .progress-info {
                display: grid;
                grid-template-columns: 1fr 1fr 2fr;
                gap: 1rem;
                margin-top: 1rem;
                font-size: 0.9rem;
                color: #7f8c8d;
            }
            
            .progress-info > div {
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
                min-width: 0; /* Important for grid items to shrink */
            }
            
            .progress-info #current {
                max-width: 100%;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
                display: inline-block;
                word-break: break-all;
            }
            /* Filters */
            .filters-section {
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(10px);
                border-radius: 12px;
                padding: 1.5rem;
                box-shadow: 0 8px 32px rgba(0,0,0,0.1);
                border: 1px solid rgba(255,255,255,0.2);
                margin-bottom: 2rem;
            }
            .filters-grid {
                display: grid;
                grid-template-columns: 2fr 1fr;
                gap: 1rem;
                align-items: end;
            }
            .filters-section input, .filters-section select {
                padding: 0.75rem;
                border: 2px solid #ecf0f1;
                border-radius: 8px;
                background: #fafbfc;
                transition: border-color 0.3s ease;
                font-size: 0.9rem;
            }
            .filters-section input:focus, .filters-section select:focus {
                outline: none;
                border-color: #3498db;
                background: white;
            }
            /* Table Styles */
            .results-section {
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(10px);
                border-radius: 12px;
                padding: 2rem;
                box-shadow: 0 8px 32px rgba(0,0,0,0.1);
                border: 1px solid rgba(255,255,255,0.2);
            }
            .table-container {
                overflow-x: auto;
                border-radius: 8px;
                border: 1px solid #ecf0f1;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                background: white;
            }
            th {
                background: linear-gradient(135deg, #34495e, #2c3e50);
                color: white;
                padding: 1rem;
                text-align: left;
                font-weight: 600;
                font-size: 0.9rem;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            td {
                padding: 1rem;
                border-bottom: 1px solid #ecf0f1;
                vertical-align: top;
            }
            
            /* URL cell specific styling */
            td:first-child {
                max-width: 300px;
                word-break: break-all;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
            }
            
            /* URL links */
            .url-link {
                color: #3498db;
                text-decoration: none;
                display: block;
                max-width: 100%;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
            }
            
            .url-link:hover {
                color: #2980b9;
                text-decoration: underline;
            }
            
            tr:hover {
                background: #f8f9fa;
            }
            .url-link {
                color: #3498db;
                text-decoration: none;
                font-weight: 500;
                transition: color 0.2s ease;
            }
            .url-link:hover {
                color: #2980b9;
                text-decoration: underline;
            }
            .status-badge {
                padding: 0.25rem 0.75rem;
                border-radius: 20px;
                font-size: 0.8rem;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            .status-safe { background: #d4edda; color: #155724; }
            .status-potential { background: #fff3cd; color: #856404; }
            .status-malicious { background: #f8d7da; color: #721c24; }
            .status-queued { background: #e2e3e5; color: #383d41; }
            .status-analyzing { background: #bee5eb; color: #0c5460; }
            .status-error { background: #f5c6cb; color: #721c24; }
            /* Table row colors */
            .queued { background-color: #f8f9fa; }
            .analyzing { background-color: #e7f3ff; }
            .judging { background-color: #fff8e1; }
            .safe { background-color: #e8f5e8; }
            .potential { background-color: #fff3cd; }
            .malicious { background-color: #fdeaea; }
            .error { background-color: #f5c6cb; }
            /* Modal Styles */
            .modal {
                display: none;
                position: fixed;
                z-index: 1000;
                left: 0;
                top: 0;
                width: 100%;
                height: 100%;
                background: rgba(0,0,0,0.5);
                backdrop-filter: blur(5px);
            }
            .modal-content {
                background: white;
                margin: 5% auto;
                padding: 2rem;
                border-radius: 12px;
                width: 90%;
                max-width: 800px;
                max-height: 80vh;
                overflow-y: auto;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            }
            .close {
                color: #aaa;
                float: right;
                font-size: 28px;
                font-weight: bold;
                cursor: pointer;
                transition: color 0.2s ease;
            }
            .close:hover { color: #333; }
            .detail-section { margin-bottom: 15px; }
            .detail-label { font-weight: bold; color: #333; }
            .server-info { background-color: #f8f9fa; padding: 10px; border-radius: 4px; margin-top: 10px; }
            .feedback-buttons { margin-top: 15px; display: flex; gap: 10px; flex-wrap: wrap; }
            .feedback-btn { padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; transition: opacity 0.2s; }
            .feedback-btn.correct { background-color: #28a745; color: white; }
            .feedback-btn.incorrect { background-color: #dc3545; color: white; }
            .feedback-btn.false-positive { background-color: #ffc107; color: #212529; }
            .feedback-btn.false-negative { background-color: #fd7e14; color: white; }
            .feedback-btn.unsure { background-color: #6c757d; color: white; }
            .feedback-btn:hover { opacity: 0.8; }
            .intelligence-section { background-color: #e9ecef; padding: 10px; border-radius: 4px; margin-top: 10px; }
            .risk-score { font-size: 18px; font-weight: bold; color: #dc3545; }
            .risk-score.low { color: #28a745; }
            .risk-score.medium { color: #ffc107; }
            .analytics-section { margin-bottom: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 8px; }
            .analytics-section h3 { margin-top: 0; color: #333; }
            .stat-card { display: inline-block; padding: 10px 15px; margin: 5px; background: #f8f9fa; border-radius: 4px; text-align: center; }
            .stat-value { font-size: 24px; font-weight: bold; color: #007bff; }
            .stat-label { font-size: 12px; color: #666; }
            /* Responsive Design */
            @media (max-width: 1200px) {
                .dashboard-grid { grid-template-columns: 1fr 1fr; }
            }
            @media (max-width: 768px) {
                .container { padding: 0 1rem; margin: 1rem auto; }
                .dashboard-grid { grid-template-columns: 1fr; }
                .filters-grid { grid-template-columns: 1fr; }
                .button-group { flex-direction: column; }
                .domain-grid { grid-template-columns: 1fr 1fr; }
                .header { padding: 1rem; }
                .header h1 { font-size: 1.8rem; }
            }
            
            /* Analyzed Images Gallery Styles */
            .analyzed-images-gallery {
                display: flex;
                flex-wrap: wrap;
                gap: 12px;
                margin-top: 12px;
            }
            
            .analyzed-image-item {
                max-width: 250px;
                min-width: 200px;
                border: 1px solid rgba(220, 220, 220, 0.8);
                border-radius: 12px;
                padding: 12px;
                background: linear-gradient(135deg, rgba(255, 255, 255, 0.95), rgba(249, 249, 249, 0.95));
                backdrop-filter: blur(10px);
                box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
                transition: all 0.3s ease;
            }
            
            .analyzed-image-item:hover {
                transform: translateY(-2px);
                box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
                border-color: rgba(0, 123, 255, 0.3);
            }
            
            .analyzed-image-item img {
                width: 100%;
                height: auto;
                max-height: 180px;
                object-fit: cover;
                border-radius: 8px;
                margin-bottom: 10px;
                border: 1px solid rgba(0, 0, 0, 0.1);
                transition: transform 0.3s ease;
            }
            
            .analyzed-image-item img:hover {
                transform: scale(1.02);
            }
            
            .analyzed-image-item .image-url {
                font-size: 11px;
                color: #666;
                word-break: break-all;
                margin-bottom: 8px;
                line-height: 1.3;
            }
            
            .analyzed-image-item .image-url a {
                color: #007bff;
                text-decoration: none;
                transition: color 0.3s ease;
            }
            
            .analyzed-image-item .image-url a:hover {
                color: #0056b3;
                text-decoration: underline;
            }
            
            .analyzed-image-item .image-analysis {
                font-size: 13px;
                color: #333;
                background: linear-gradient(135deg, rgba(232, 244, 253, 0.9), rgba(225, 245, 254, 0.9));
                padding: 8px;
                border-radius: 6px;
                border-left: 3px solid #007bff;
                line-height: 1.4;
            }
            
            .image-error-placeholder {
                padding: 30px;
                background: linear-gradient(135deg, rgba(245, 245, 245, 0.9), rgba(240, 240, 240, 0.9));
                border-radius: 8px;
                text-align: center;
                color: #666;
                font-size: 14px;
                border: 2px dashed #ddd;
            }
            
            @media (max-width: 768px) {
                .analyzed-images-gallery {
                    flex-direction: column;
                }
                .analyzed-image-item {
                    max-width: 100%;
                    min-width: auto;
                }
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛡️ C.A.K.R.A. Security Scanner</h1>
            <p class="subtitle">Comprehensive Analysis and Knowledge Risk Assessment</p>
            <div class="system-note">
                ⚠️ Advanced detection features limited - Selenium not available. Using basic pattern detection.
            </div>
        </div>
        
        <div class="container">
            <!-- Dashboard Stats -->
            <div class="dashboard-grid">
                <div class="card counter-card scanned">
                    <div class="counter-number" id="scanned">0</div>
                    <div class="counter-label">Scanned</div>
                </div>
                <div class="card counter-card potential">
                    <div class="counter-number" id="potential">0</div>
                    <div class="counter-label">Potential Risk</div>
                </div>
                <div class="card counter-card dangerous">
                    <div class="counter-number" id="dangerous">0</div>
                    <div class="counter-label">High Risk</div>
                </div>
                <div class="card counter-card found">
                    <div class="counter-number" id="found">0</div>
                    <div class="counter-label">Sites Found</div>
                </div>
            </div>

            <!-- Progress Section -->
            <div class="progress-section" id="progress" style="display: none;">
                <h3>📊 Scan Progress</h3>
                <div class="progress-bar-container">
                    <div class="progress-bar" id="progressFill" style="width: 0%;"></div>
                </div>
                <div class="progress-info">
                    <div><strong>Progress:</strong> <span id="percentage">0</span>% (<span id="completed">0</span>/<span id="total">0</span>)</div>
                    <div><strong>ETA:</strong> <span id="eta">0</span> seconds</div>
                    <div><strong>Current:</strong> <span id="current">Ready</span></div>
                </div>
                <div style="text-align: center; margin-top: 1rem;">
                    <p id="statusSummary" style="font-weight: 600; color: #2c3e50;">Ready to scan</p>
                </div>
            </div>

            <!-- Control Panel -->
            <div class="control-panel">
                <h3>🎯 Scan Configuration</h3>
                <form id="scanForm">
                    <div class="form-section">
                        <label for="urls">🌐 Target URLs (one per line):</label>
                        <textarea name="urls" id="urls" placeholder="https://example.com&#10;https://another-site.com&#10;&#10;Enter URLs to scan for security threats..."></textarea>
                    </div>
                    
                    <div class="form-section">
                        <label>🔍 Domain Discovery & Search:</label>
                        <div class="domain-grid">
                            <label class="domain-checkbox"><input type="checkbox" name="domains" value=".id"> .id</label>
                            <label class="domain-checkbox"><input type="checkbox" name="domains" value=".go.id"> .go.id</label>
                            <label class="domain-checkbox"><input type="checkbox" name="domains" value=".ac.id"> .ac.id</label>
                            <label class="domain-checkbox"><input type="checkbox" name="domains" value=".co.id"> .co.id</label>
                            <label class="domain-checkbox"><input type="checkbox" name="domains" value=".or.id"> .or.id</label>
                            <label class="domain-checkbox"><input type="checkbox" name="domains" value=".net.id"> .net.id</label>
                            <label class="domain-checkbox"><input type="checkbox" name="domains" value=".web.id"> .web.id</label>
                            <label class="domain-checkbox"><input type="checkbox" name="domains" value=".sch.id"> .sch.id</label>
                            <label class="domain-checkbox"><input type="checkbox" name="domains" value=".mil.id"> .mil.id</label>
                            <label class="domain-checkbox"><input type="checkbox" name="domains" value=".edu"> .edu</label>
                            <label class="domain-checkbox"><input type="checkbox" name="domains" value=".gov.id"> .gov.id</label>
                            <label class="domain-checkbox"><input type="checkbox" name="domains" value=".com"> .com</label>
                            <label class="domain-checkbox"><input type="checkbox" name="domains" value=".org"> .org</label>
                            <label class="domain-checkbox"><input type="checkbox" name="domains" value=".net"> .net</label>
                        </div>
                    </div>
                    
                    <div class="button-group">
                        <button type="submit" class="btn btn-primary" id="scanButton">
                            🚀 Start Security Scan
                        </button>
                        <button type="button" class="btn btn-secondary" id="exportButton">
                            📄 Export PDF Report
                        </button>
                        <button type="button" class="btn btn-accent" id="analyticsButton">
                            📊 View Analytics
                        </button>
                    </div>
                </form>
            </div>

            <!-- Filters -->
            <div class="filters-section">
                <h3>🔍 Filter Results</h3>
                <div class="filters-grid">
                    <div>
                        <label>Search URLs:</label>
                        <input type="text" id="searchInput" placeholder="Search by URL, domain, or content...">
                    </div>
                    <div>
                        <label>Filter by Status:</label>
                        <select id="judgmentFilter">
                            <option value="">All Results</option>
                            <option value="Queued">⏳ Queued</option>
                            <option value="Analyzing in Progress">🔄 Analyzing</option>
                            <option value="Judging in Progress">⚖️ Judging</option>
                            <option value="Safe">✅ Safe</option>
                            <option value="Potential">⚠️ Potential Risk</option>
                            <option value="Malicious">🚨 High Risk</option>
                            <option value="Error">❌ Error</option>
                        </select>
                    </div>
                </div>
            </div>

            <!-- Results -->
            <div class="results-section">
                <h3>📊 Scan Results</h3>
                <div class="table-container">
                    <table id="resultsTable">
                        <thead>
                            <tr>
                                <th>🌐 URL</th>
                                <th>📊 Confidence</th>
                                <th>⚖️ Security Status</th>
                                <th>📝 Text Analysis</th>
                                <th>👁️ Vision Analysis</th>
                            </tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <!-- Modal for URL details -->
            <div id="urlModal" class="modal">
                <div class="modal-content">
                    <span class="close">&times;</span>
                    <h2>Website Details</h2>
                    <div id="modalContent"></div>
                </div>
            </div>
            
            <!-- Modal for Analytics -->
            <div id="analyticsModal" class="modal">
                <div class="modal-content" style="max-width: 1000px;">
                    <span class="close" onclick="closeAnalyticsModal()">&times;</span>
                    <h2>Analytics Dashboard</h2>
                    <div id="analyticsContent">
                        <div class="analytics-section">
                            <h3>Overall Statistics</h3>
                            <div id="overallStats"></div>
                        </div>
                        <div class="analytics-section">
                            <h3>AI Performance</h3>
                            <div id="aiPerformance"></div>
                        </div>
                        <div class="analytics-section">
                            <h3>Top Domains</h3>
                            <div id="topDomains"></div>
                        </div>
                        <div class="analytics-section">
                            <h3>Recent Activity</h3>
                            <div id="recentActivity"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            const socket = io();
            const resultsTable = document.querySelector('#resultsTable tbody');
            const statusDiv = document.getElementById('status');
            const scannedDiv = document.getElementById('scanned');
            const potentialDiv = document.getElementById('potential');
            const dangerousDiv = document.getElementById('dangerous');
            let scanned = 0, potential = 0, dangerous = 0;
            let urlData = {};  // Store latest data for each URL
            
            socket.on('connect', function() {
                socket.emit('request_initial');
            });
            
            socket.on('scan_status', function(data) {
                const button = document.getElementById('scanButton');
                const statusSummary = document.getElementById('statusSummary');
                const progressSection = document.getElementById('progress');
                
                if (data.scanning) {
                    button.textContent = 'Stop Scan';
                    statusSummary.textContent = 'Scanning in progress...';
                    progressSection.style.display = 'block';
                } else {
                    button.textContent = 'Start Scan';
                    statusSummary.textContent = 'Scan completed or stopped';
                    progressSection.style.display = 'none';
                }
            });
            
            socket.on('progress', function(data) {
                document.getElementById('percentage').textContent = data.percentage;
                document.getElementById('eta').textContent = data.eta;
                // Truncate long URLs in current scanning display
                const currentUrls = data.current_scanning.map(url => {
                    if (url.length > 50) {
                        return url.substring(0, 47) + '...';
                    }
                    return url;
                });
                document.getElementById('current').textContent = currentUrls.join(', ');
                document.getElementById('progressFill').style.width = data.percentage + '%';
                document.getElementById('completed').textContent = data.completed || 0;
                document.getElementById('total').textContent = data.total || 0;
            });
            
            socket.on('total_sites', function(count) {
                document.getElementById('found').textContent = count;
                document.getElementById('total').textContent = count;
            });
            
            socket.on('dashboard_update', function(data) {
                // Update dashboard counters in real-time during scanning
                scanned = data.scanned;
                potential = data.potential;
                dangerous = data.dangerous;
                scannedDiv.textContent = scanned;
                potentialDiv.textContent = potential;
                dangerousDiv.textContent = dangerous;
                document.getElementById('found').textContent = data.found;
            });
            
            socket.on('reset', function() {
                scanned = 0;
                potential = 0;
                dangerous = 0;
                scannedDiv.textContent = '0';
                potentialDiv.textContent = '0';
                dangerousDiv.textContent = '0';
                document.getElementById('found').textContent = '0';
                document.getElementById('percentage').textContent = '0';
                document.getElementById('eta').textContent = '0';
                document.getElementById('current').textContent = 'Ready';
                document.getElementById('progress').style.display = 'block';
                resultsTable.innerHTML = '';
                // Request initial state to repopulate with existing results
                socket.emit('request_initial');
            });
            
            socket.on('scan_update', function(data) {
                // Find row for this URL
                let existingRow = Array.from(resultsTable.rows).find(row => row.cells[0].textContent.trim() === data.url);
                let wasQueued = false;
                if (existingRow) {
                    // If previously queued, now analyzed, increment scanned
                    if (existingRow.cells[2].innerHTML === 'Queued' && data.judgment !== 'Queued') {
                        scanned++;
                        scannedDiv.textContent = scanned;
                        // Parse judgment for counters with null safety
                        const judgment = (data.judgment || '').toLowerCase();
                        if (judgment.includes('malicious') || judgment.includes('dangerous')) {
                            dangerous++;
                            dangerousDiv.textContent = dangerous;
                        } else if (judgment.includes('potential') || judgment.includes('suspicious')) {
                            potential++;
                            potentialDiv.textContent = potential;
                        }
                    }
                    // Update row with safe judgment handling
                    const safeJudgment = data.judgment || 'Unknown';
                    existingRow.cells[1].innerHTML = data.confidence || 'N/A';
                    existingRow.cells[2].innerHTML = safeJudgment;
                    // Simplify display for table
                    let textDisplay = safeJudgment === 'Queued' ? 'Queued' : (safeJudgment === 'Error' ? 'Error' : 'Done');
                    let visionDisplay = safeJudgment === 'Queued' ? 'Queued' : (safeJudgment === 'Error' ? 'Error' : 'Done');
                    existingRow.cells[3].innerHTML = textDisplay;
                    existingRow.cells[4].innerHTML = visionDisplay;
                    let rowClass = safeJudgment.toLowerCase().replace(/\s+/g, '').replace('inprogress', '');
                    existingRow.className = rowClass;
                    existingRow.dataset.judgment = safeJudgment;  // Update dataset for filtering
                } else {
                    // Create new row with safe judgment handling
                    const row = document.createElement('tr');
                    const safeJudgment = data.judgment || 'Unknown';
                    // Simplify display for table
                    let textDisplay = safeJudgment === 'Queued' ? 'Queued' : (safeJudgment === 'Error' ? 'Error' : 'Done');
                    let visionDisplay = safeJudgment === 'Queued' ? 'Queued' : (safeJudgment === 'Error' ? 'Error' : 'Done');
                    let rowClass = safeJudgment.toLowerCase().replace(/\s+/g, '').replace('inprogress', '');
                    row.className = rowClass;
                    row.dataset.judgment = safeJudgment;  // Set dataset for filtering
                    row.innerHTML = `
                        <td><a href="#" class="url-link" data-url="${data.url || ''}">${data.url || 'Unknown URL'}</a></td>
                        <td>${data.confidence || 'N/A'}</td>
                        <td>${safeJudgment}</td>
                        <td>${textDisplay}</td>
                        <td>${visionDisplay}</td>
                    `;
                    resultsTable.appendChild(row);
                    // Add click handler for the new URL
                    const newLink = row.querySelector('.url-link');
                    if (newLink) {
                        newLink.addEventListener('click', function(e) {
                            e.preventDefault();
                            showUrlDetails(urlData[this.getAttribute('data-url')]);
                        });
                    }
                }
                
                // Update the data for this URL
                urlData[data.url] = data;
            });
            
            socket.on('initial_state', function(data) {
                scanned = data.scanned;
                potential = data.potential;
                dangerous = data.dangerous;
                        scannedDiv.textContent = scanned;
                        potentialDiv.textContent = potential;
                        dangerousDiv.textContent = dangerous;
                        // Use the 'found' counter for total discovered sites
                        if (data.found !== undefined) {
                            document.getElementById('found').textContent = data.found;
                        }
                
                // Clear existing table first
                resultsTable.innerHTML = '';
                
                // Populate table
                data.results.forEach(result => {
                    const row = document.createElement('tr');
                    // Safe judgment handling with null checks
                    const judgment = result.judgment || 'Unknown';
                    // Simplify display for table
                    let textDisplay = judgment === 'Queued' ? 'Queued' : (judgment === 'Error' ? 'Error' : 'Done');
                    let visionDisplay = judgment === 'Queued' ? 'Queued' : (judgment === 'Error' ? 'Error' : 'Done');
                    let rowClass = judgment.toLowerCase().replace(/\s+/g, '').replace('inprogress', '');
                    row.className = rowClass;
                    row.dataset.judgment = judgment;
                    row.innerHTML = `
                        <td><a href="#" class="url-link" data-url="${result.url || ''}">${result.url || 'Unknown URL'}</a></td>
                        <td>${result.confidence || 'N/A'}</td>
                        <td>${judgment}</td>
                        <td>${textDisplay}</td>
                        <td>${visionDisplay}</td>
                    `;
                    resultsTable.appendChild(row);
                    
                    // Add click handler for existing URLs
                    const link = row.querySelector('.url-link');
                    if (link) {
                        link.addEventListener('click', function(e) {
                            e.preventDefault();
                            showUrlDetails(urlData[this.getAttribute('data-url')]);
                        });
                    }
                    
                    // Set data for this URL
                    urlData[result.url] = result;
                });
            });
            
            function showUrlDetails(data) {
                const modal = document.getElementById('urlModal');
                const modalContent = document.getElementById('modalContent');
                
                let serverInfoHtml = '';
                if (data.server_info) {
                    // Check if any field has real data
                    const s = data.server_info;
                    const hasRealInfo = [s.server, s.ip_address, s.status_code, s.content_type, s.last_modified, s.content_length].some(v => v && v !== 'Unknown');
                    if (hasRealInfo) {
                        serverInfoHtml = `
                            <div class="detail-section server-info">
                                <div class="detail-label">Server Information:</div>
                                <ul>
                                    <li><strong>Server:</strong> ${s.server || 'Unknown'}</li>
                                    <li><strong>IP Address:</strong> ${s.ip_address || 'Unknown'}</li>
                                    <li><strong>Status Code:</strong> ${s.status_code || 'Unknown'}</li>
                                    <li><strong>Content Type:</strong> ${s.content_type || 'Unknown'}</li>
                                    <li><strong>Last Modified:</strong> ${s.last_modified || 'Unknown'}</li>
                                    <li><strong>Content Length:</strong> ${s.content_length || 'Unknown'}</li>
                                    <li><strong>Response Time:</strong> ${s.response_time || 'Unknown'} seconds</li>
                                    ${s.ssl_info && s.ssl_info.valid ? `<li><strong>SSL Valid:</strong> Yes (Issuer: ${s.ssl_info.issuer.O || 'Unknown'})</li>` : `<li><strong>SSL Valid:</strong> No</li>`}
                                    ${s.final_url && s.final_url !== data.url ? `<li><strong>Redirected To:</strong> ${s.final_url}</li>` : ''}
                                    ${s.anti_crawler_indicators && s.anti_crawler_indicators.length > 0 ? `<li><strong>Anti-Crawler Detected:</strong> ${s.anti_crawler_indicators.join(', ')}</li>` : ''}
                                    ${s.used_selenium ? `<li><strong>Used Headless Browser:</strong> Yes (bypassed JS anti-crawler)</li>` : ''}
                                </ul>
                            </div>
                        `;
                    } else {
                        serverInfoHtml = `
                            <div class="detail-section server-info">
                                <div class="detail-label">Server Information:</div>
                                <p>Not Found</p>
                            </div>
                        `;
                    }
                } else {
                    serverInfoHtml = `
                        <div class="detail-section server-info">
                            <div class="detail-label">Server Information:</div>
                            <p>Not Found</p>
                        </div>
                    `;
                }
                let shadowdoorHtml = '';
                if (data.shadowdoor_links && data.shadowdoor_links.length > 0) {
                    shadowdoorHtml = `
                        <div class="detail-section" style="background-color: #ffe6e6; padding: 10px; border-radius: 4px; margin-top: 10px;">
                            <div class="detail-label" style="color: #d9534f;">🚨 Shadowdoor Links Detected:</div>
                            <ul>
                                ${data.shadowdoor_links.map(link => `
                                    <li><strong>${link.category}:</strong> <a href="${link.url}" target="_blank">${link.url}</a> (${link.anchor_text})</li>
                                `).join('')}
                            </ul>
                        </div>
                    `;
                }
                
                let vulnerabilitiesHtml = '';
                if (data.vulnerabilities && data.vulnerabilities.length > 0) {
                    vulnerabilitiesHtml = `
                        <div class="detail-section" style="background-color: #fff3cd; padding: 10px; border-radius: 4px; margin-top: 10px;">
                            <div class="detail-label" style="color: #856404;">⚠️ Security Vulnerabilities:</div>
                            <ul>
                                ${data.vulnerabilities.map(vuln => `
                                    <li><strong>${vuln.severity.toUpperCase()}:</strong> ${vuln.description}<br>
                                        <em>Recommendation: ${vuln.recommendation}</em></li>
                                `).join('')}
                            </ul>
                        </div>
                    `;
                }
                
                let intelligenceHtml = '';
                if (data.domain_intelligence) {
                    const intel = data.domain_intelligence;
                    const riskClass = intel.risk_score > 70 ? 'high' : intel.risk_score > 40 ? 'medium' : 'low';
                    intelligenceHtml = `
                        <div class="detail-section intelligence-section">
                            <div class="detail-label">🔍 Domain Intelligence:</div>
                            <div class="risk-score ${riskClass}">Risk Score: ${intel.risk_score}/100</div>
                            ${intel.risk_factors && intel.risk_factors.length > 0 ? `
                                <div><strong>Risk Factors:</strong></div>
                                <ul>
                                    ${intel.risk_factors.map(factor => `<li>${factor}</li>`).join('')}
                                </ul>
                            ` : ''}
                            ${intel.recommendations && intel.recommendations.length > 0 ? `
                                <div><strong>Recommendations:</strong></div>
                                <ul>
                                    ${intel.recommendations.map(rec => `<li>${rec}</li>`).join('')}
                                </ul>
                            ` : ''}
                        </div>
                    `;
                }
                
                modalContent.innerHTML = `
                    <div class="detail-section">
                        <div class="detail-label">URL:</div>
                        <a href="${data.url}" target="_blank">${data.url}</a>
                    </div>
                    <div class="detail-section">
                        <div class="detail-label">Confidence Score:</div>
                        ${data.confidence || 'N/A'}
                    </div>
                    <div class="detail-section">
                        <div class="detail-label">Judgment:</div>
                        ${data.judgment}
                    </div>
                    <div class="detail-section">
                        <div class="detail-label">Text Analysis:</div>
                        ${data.text_result || 'No analysis available'}
                    </div>
                    <div class="detail-section">
                        <div class="detail-label">Vision Analysis:</div>
                        ${data.vision_results ? data.vision_results.join('<br>') : 'No vision analysis available'}
                    </div>
                    ${data.analyzed_images && data.analyzed_images.length > 0 ? `
                        <div class="detail-section">
                            <div class="detail-label">🖼️ Analyzed Images:</div>
                            <div class="analyzed-images-gallery">
                                ${data.analyzed_images.map((img, index) => `
                                    <div class="analyzed-image-item">
                                        <img src="${img.url}" alt="Analyzed Image ${index + 1}" 
                                             onerror="this.style.display='none'; this.nextElementSibling.style.display='block';">
                                        <div class="image-error-placeholder" style="display: none;">
                                            ❌ Image not available
                                        </div>
                                        <div class="image-url">
                                            <a href="${img.url}" target="_blank">${img.url}</a>
                                        </div>
                                        ${img.analysis ? `<div class="image-analysis"><strong>Analysis:</strong> ${img.analysis}</div>` : ''}
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    ` : ''}
                    ${serverInfoHtml}
                    ${shadowdoorHtml}
                    ${vulnerabilitiesHtml}
                    ${intelligenceHtml}
                    <div class="detail-section feedback-buttons">
                        <div class="detail-label">AI Feedback (helps improve accuracy):</div>
                        <div style="display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px;">
                            <button class="feedback-btn correct" onclick="submitDetailedFeedback('${data.url}', 'correct')">Verdict is Correct</button>
                            <button class="feedback-btn incorrect" onclick="submitDetailedFeedback('${data.url}', 'incorrect')">Verdict is Incorrect</button>
                            <button class="feedback-btn" style="background-color: #ffc107; color: black;" onclick="submitDetailedFeedback('${data.url}', 'false_positive')">False Positive</button>
                            <button class="feedback-btn" style="background-color: #17a2b8; color: white;" onclick="submitDetailedFeedback('${data.url}', 'false_negative')">False Negative</button>
                            <button class="feedback-btn" style="background-color: #6c757d; color: white;" onclick="submitDetailedFeedback('${data.url}', 'unsure')">Unsure</button>
                        </div>
                    </div>
                    ${data.error ? `<div class="detail-section"><div class="detail-label">Error:</div><span class="error">${data.error}</span></div>` : ''}
                `;
                
                modal.style.display = 'block';
            }
            
            // Modal close functionality
            document.querySelector('.close').addEventListener('click', function() {
                document.getElementById('urlModal').style.display = 'none';
            });
            
            window.addEventListener('click', function(event) {
                const modal = document.getElementById('urlModal');
                if (event.target === modal) {
                    modal.style.display = 'none';
                }
            });
            
            document.getElementById('scanForm').addEventListener('submit', function(e) {
                e.preventDefault();
                // Don't reset counters here - let server handle them
                // Don't clear table here - let server send reset signal if needed
                const formData = new FormData(this);
                fetch('/scan', {
                    method: 'POST',
                    body: formData
                }).then(response => response.json()).then(data => {
                    statusDiv.textContent = data.status;
                });
            });
            
            document.getElementById('analyticsButton').addEventListener('click', showAnalytics);
            document.getElementById('exportButton').addEventListener('click', function() {
                window.open('/export_pdf', '_blank');
            });
            
            function showAnalytics() {
                fetch('/analytics')
                    .then(response => response.json())
                    .then(data => {
                        displayAnalytics(data);
                        document.getElementById('analyticsModal').style.display = 'block';
                    })
                    .catch(error => {
                        console.error('Error loading analytics:', error);
                        alert('Error loading analytics data');
                    });
            }
            
            function closeAnalyticsModal() {
                document.getElementById('analyticsModal').style.display = 'none';
            }
            
            function displayAnalytics(data) {
                // Overall Statistics
                const overallStats = data.overall_stats || {};
                document.getElementById('overallStats').innerHTML = `
                    <div class="stat-card">
                        <div class="stat-value">${overallStats.total_scanned || 0}</div>
                        <div class="stat-label">Total Scanned</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" style="color: #dc3545;">${overallStats.dangerous_count || 0}</div>
                        <div class="stat-label">Dangerous</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" style="color: #ffc107;">${overallStats.potential_count || 0}</div>
                        <div class="stat-label">Potential</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" style="color: #28a745;">${overallStats.safe_count || 0}</div>
                        <div class="stat-label">Safe</div>
                    </div>
                `;
                
                // AI Performance
                const feedbackStats = data.feedback_stats || {};
                document.getElementById('aiPerformance').innerHTML = `
                    <div class="stat-card">
                        <div class="stat-value">${feedbackStats.total_feedback || 0}</div>
                        <div class="stat-label">Total Feedback</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" style="color: #28a745;">${(feedbackStats.accuracy_rate || 0).toFixed(1)}%</div>
                        <div class="stat-label">Accuracy Rate</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">${feedbackStats.correct_feedback || 0}</div>
                        <div class="stat-label">Correct</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" style="color: #dc3545;">${feedbackStats.incorrect_feedback || 0}</div>
                        <div class="stat-label">Incorrect</div>
                    </div>
                `;
                
                // Top Domains
                const domainStats = data.domain_stats || {};
                let domainHtml = '<table style="width: 100%; border-collapse: collapse;">';
                domainHtml += '<tr><th style="border: 1px solid #ddd; padding: 8px;">Domain</th><th style="border: 1px solid #ddd; padding: 8px;">Scans</th><th style="border: 1px solid #ddd; padding: 8px;">Avg Confidence</th><th style="border: 1px solid #ddd; padding: 8px;">Risk Level</th></tr>';
                
                (domainStats.top_domains || []).slice(0, 10).forEach(domain => {
                    const riskColor = domain.dangerous_count > domain.total_scans * 0.5 ? '#dc3545' : 
                                     domain.potential_count > domain.total_scans * 0.3 ? '#ffc107' : '#28a745';
                    domainHtml += `<tr>
                        <td style="border: 1px solid #ddd; padding: 8px;">${domain.domain}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">${domain.total_scans}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">${domain.avg_confidence}%</td>
                        <td style="border: 1px solid #ddd; padding: 8px; color: ${riskColor};">${domain.dangerous_count > 0 ? 'High' : domain.potential_count > 0 ? 'Medium' : 'Low'}</td>
                    </tr>`;
                });
                domainHtml += '</table>';
                document.getElementById('topDomains').innerHTML = domainStats.top_domains && domainStats.top_domains.length > 0 ? domainHtml : 'No domain data available';
                
                // Recent Activity (placeholder)
                document.getElementById('recentActivity').innerHTML = '<p>Recent activity chart would be displayed here</p>';
            }
            
            function filterResults() {
                const searchTerm = document.getElementById('searchInput').value.toLowerCase();
                const judgmentFilter = document.getElementById('judgmentFilter').value;
                const rows = resultsTable.querySelectorAll('tbody tr');
                
                rows.forEach(row => {
                    const url = row.cells[0].textContent.toLowerCase();
                    const judgment = row.cells[2].textContent;
                    
                    const matchesSearch = url.includes(searchTerm);
                    const matchesJudgment = !judgmentFilter || judgment === judgmentFilter;
                    
                    row.style.display = matchesSearch && matchesJudgment ? '' : 'none';
                });
            }
            
            function submitFeedback(url, feedbackType) {
                submitDetailedFeedback(url, feedbackType);
            }
            
            function submitDetailedFeedback(url, feedbackType) {
                const userComment = prompt('Optional comment (helps us improve):', '');
                
                fetch('/submit_feedback', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        url: url,
                        feedback_type: feedbackType,
                        user_comment: userComment || '',
                        detailed_feedback: {
                            user_agent: navigator.userAgent,
                            timestamp: new Date().toISOString(),
                            feedback_source: 'web_ui'
                        }
                    })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('Thank you for your feedback! This helps improve the AI analysis.');
                    } else {
                        alert('Error submitting feedback: ' + data.error);
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('Error submitting feedback');
                });
            }
            
            // Add event listeners for search and filter
            document.getElementById('searchInput').addEventListener('input', filterResults);
            document.getElementById('judgmentFilter').addEventListener('change', filterResults);
            
            // Filter results function
            function filterResults() {
                const searchTerm = document.getElementById('searchInput').value.toLowerCase();
                const judgmentFilter = document.getElementById('judgmentFilter').value;
                const tableRows = document.querySelectorAll('#resultsTable tbody tr');
                
                tableRows.forEach(row => {
                    const text = row.textContent.toLowerCase();
                    const judgment = row.dataset.judgment || '';
                    
                    const matchesSearch = text.includes(searchTerm);
                    const matchesJudgment = judgmentFilter === '' || judgment === judgmentFilter;
                    
                    if (matchesSearch && matchesJudgment) {
                        row.style.display = '';
                    } else {
                        row.style.display = 'none';
                    }
                });
            }
        </script>
    </body>
    </html>
    """
    return render_template_string(html)

@app.route('/scan', methods=['POST'])
def scan():
    global scan_thread, scanned_count, potential_count, dangerous_count, scan_results, total_sites, stop_scan, is_scanning, total_scanning_sites
    
    # Initialize counters if not already done
    if 'scanned_count' not in globals():
        scanned_count = 0
        potential_count = 0
        dangerous_count = 0
        total_sites = 0
        total_scanning_sites = 0
    
    if is_scanning:
        stop_scan = True
        is_scanning = False
        socketio.emit('scan_status', {'scanning': False})
        return jsonify({'status': 'Stopping scan'})
    
    urls = request.form['urls'].strip().split('\n')
    urls = [url.strip() for url in urls if url.strip()]
    domains = request.form.getlist('domains')
    keywords = list(MALICIOUS_KEYWORDS)
    
    if keywords and domains:
        dork_urls = google_dork_search(keywords, domains)
        urls.extend(dork_urls)
    
    # Remove duplicates and filter out already scanned URLs
    unique_urls = list(set(urls))
    already_scanned = {result['url'] for result in scan_results}
    new_urls = [url for url in unique_urls if url not in already_scanned]
    
    total_sites = len(unique_urls)  # Total unique sites found (for "Sites Found" counter)
    total_scanning_sites = len(new_urls)  # Total new sites to scan (for progress calculation)
    socketio.emit('total_sites', total_sites)  # Show total found sites
    
    if not new_urls:
        return jsonify({'status': 'All URLs already scanned'})
    
    scanned_count = len(scan_results)  # Start from existing count
    # Recalculate counters from existing results
    potential_count = sum(1 for result in scan_results if 'potential' in (result.get('judgment') or '').lower() or 'suspicious' in (result.get('judgment') or '').lower())
    dangerous_count = sum(1 for result in scan_results if 'malicious' in (result.get('judgment') or '').lower() or 'dangerous' in (result.get('judgment') or '').lower())
    stop_scan = False
    is_scanning = True
    socketio.emit('reset')
    socketio.emit('total_sites', total_sites)  # Emit total found sites
    socketio.emit('scan_status', {'scanning': True})
    
    scan_thread = threading.Thread(target=lambda: parallel_scan(new_urls))
    scan_thread.start()
    
    return jsonify({'status': 'Scan started'})

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    """Handle user feedback for AI learning."""
    try:
        data = request.get_json()
        url = data.get('url')
        feedback_type = data.get('feedback_type')
        user_comment = data.get('user_comment', '')
        detailed_feedback = data.get('detailed_feedback', {})
        
        if not url or feedback_type not in ['correct', 'incorrect', 'false_positive', 'false_negative', 'unsure']:
            return jsonify({'success': False, 'error': 'Invalid feedback data'})
        
        success = db.save_feedback(url, feedback_type, user_comment, detailed_feedback)
        
        if success:
            # Update malicious keywords if new ones were found
            result = db.get_scan_result(url)
            if result and result.get('new_keywords'):
                config.update_malicious_keywords(result['new_keywords'])
            
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Failed to save feedback'})
            
    except Exception as e:
        logging.error(f"Error submitting feedback: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/analytics')
def get_analytics():
    """Get analytics data for dashboard."""
    try:
        # Get various statistics
        stats = db.get_statistics()
        feedback_stats = db.get_feedback_stats()
        domain_stats = db.get_domain_statistics()
        time_series = db.get_time_series_stats(days=30)
        
        return jsonify({
            'overall_stats': stats,
            'feedback_stats': feedback_stats,
            'domain_stats': domain_stats,
            'time_series': time_series
        })
    except Exception as e:
        logging.error(f"Error getting analytics: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/advanced_search', methods=['POST'])
def advanced_search():
    """Perform advanced search on scan results."""
    try:
        filters = request.get_json()
        limit = filters.pop('limit', 100)
        offset = filters.pop('offset', 0)
        
        results = db.advanced_query(filters, limit=limit, offset=offset)
        
        return jsonify({
            'success': True,
            'results': results,
            'count': len(results)
        })
    except Exception as e:
        logging.error(f"Error in advanced search: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/export_pdf')
def export_pdf():
    """Export scan results to PDF report."""
    try:
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from reportlab.lib.units import inch
        from reportlab.graphics.shapes import Drawing
        from reportlab.graphics.charts.piecharts import Pie
        from reportlab.graphics.charts.barcharts import VerticalBarChart
        import matplotlib.pyplot as plt
        import base64
        from datetime import datetime
        
        # Get all results and statistics from database
        all_results = db.get_all_scan_results()
        stats = db.get_statistics()
        
        # Create PDF buffer
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=50)
        
        # Get styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=1,  # Center alignment
            textColor=colors.darkblue
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.darkblue
        )
        
        # Build PDF content
        content = []
        
        # Title page
        content.append(Paragraph("C.A.K.R.A. Security Scan Report", title_style))
        content.append(Spacer(1, 20))
        content.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        content.append(Spacer(1, 30))
        
        # Executive Summary
        content.append(Paragraph("Executive Summary", heading_style))
        summary_data = [
            ['Metric', 'Count'],
            ['Total Sites Scanned', str(stats.get('total_scanned', 0))],
            ['Safe Sites', str(stats.get('safe_count', 0))],
            ['Potentially Dangerous Sites', str(stats.get('potential_count', 0))],
            ['Dangerous Sites', str(stats.get('dangerous_count', 0))],
            ['Errors Encountered', str(stats.get('error_count', 0))]
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        content.append(summary_table)
        content.append(Spacer(1, 30))
        
        # Risk Distribution Chart (if we have data)
        if stats.get('total_scanned', 0) > 0:
            content.append(Paragraph("Risk Distribution", heading_style))
            
            # Create pie chart data
            safe = stats.get('safe_count', 0)
            potential = stats.get('potential_count', 0)
            dangerous = stats.get('dangerous_count', 0)
            
            if safe + potential + dangerous > 0:
                chart_data = []
                if safe > 0:
                    chart_data.append(('Safe', safe, colors.green))
                if potential > 0:
                    chart_data.append(('Potential Risk', potential, colors.orange))
                if dangerous > 0:
                    chart_data.append(('Dangerous', dangerous, colors.red))
                
                content.append(Paragraph(f"Safe: {safe} | Potential Risk: {potential} | Dangerous: {dangerous}", styles['Normal']))
                content.append(Spacer(1, 20))
        
        # Detailed Results
        if all_results:
            content.append(PageBreak())
            content.append(Paragraph("Detailed Scan Results", heading_style))
            
            # Create table data
            table_data = [['URL', 'Judgment', 'Confidence', 'Risk Factors']]
            
            for result in all_results[:50]:  # Limit to first 50 results for PDF size
                url = result.get('url', '')[:60] + '...' if len(result.get('url', '')) > 60 else result.get('url', '')
                judgment = result.get('judgment', 'Unknown')
                confidence = f"{result.get('confidence', 'N/A')}%" if result.get('confidence') else 'N/A'
                
                # Extract risk factors from intelligence data
                risk_factors = []
                if result.get('domain_intelligence'):
                    risk_factors = result['domain_intelligence'].get('risk_factors', [])
                
                risk_str = '; '.join(risk_factors[:3]) if risk_factors else 'None detected'
                if len(risk_str) > 80:
                    risk_str = risk_str[:77] + '...'
                
                table_data.append([url, judgment, confidence, risk_str])
            
            # Create and style the table
            results_table = Table(table_data, colWidths=[2.5*inch, 1.2*inch, 0.8*inch, 2.5*inch])
            results_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))
            
            content.append(results_table)
            
            # Add note if we limited results
            if len(all_results) > 50:
                content.append(Spacer(1, 10))
                content.append(Paragraph(f"Note: Showing first 50 results of {len(all_results)} total results.", styles['Italic']))
        
        # Intelligence Summary
        if all_results:
            content.append(PageBreak())
            content.append(Paragraph("Intelligence Summary", heading_style))
            
            # Count intelligence findings
            high_risk_domains = 0
            domains_with_intel = 0
            common_risk_factors = {}
            
            for result in all_results:
                if result.get('domain_intelligence'):
                    domains_with_intel += 1
                    intel = result['domain_intelligence']
                    
                    if intel.get('risk_score', 0) >= 70:
                        high_risk_domains += 1
                    
                    # Count risk factors
                    for factor in intel.get('risk_factors', []):
                        common_risk_factors[factor] = common_risk_factors.get(factor, 0) + 1
            
            intel_summary = [
                ['Intelligence Metric', 'Count'],
                ['Domains with Intelligence Data', str(domains_with_intel)],
                ['High Risk Domains (Score ≥ 70)', str(high_risk_domains)],
            ]
            
            # Add top risk factors
            if common_risk_factors:
                sorted_factors = sorted(common_risk_factors.items(), key=lambda x: x[1], reverse=True)
                intel_summary.append(['', ''])
                intel_summary.append(['Top Risk Factors', 'Occurrences'])
                for factor, count in sorted_factors[:5]:
                    factor_short = factor[:40] + '...' if len(factor) > 40 else factor
                    intel_summary.append([factor_short, str(count)])
            
            intel_table = Table(intel_summary, colWidths=[4*inch, 1.5*inch])
            intel_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            
            content.append(intel_table)
        
        # Footer
        content.append(Spacer(1, 50))
        content.append(Paragraph("Report generated by C.A.K.R.A. (Cyber Analysis and Knowledge Repository Assistant)", styles['Italic']))
        
        # Build PDF
        doc.build(content)
        buffer.seek(0)
        
        return send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'cakra_security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        )
        
    except Exception as e:
        logging.error(f"Error exporting PDF: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    # Initialize global variables
    global scanned_count, potential_count, dangerous_count, total_sites
    scanned_count = 0
    potential_count = 0
    dangerous_count = 0
    total_sites = 0
    
    # Load existing results from database on startup
    logging.info("Loading existing scan results from database...")
    all_results = db.get_all_scan_results()
    scan_results.extend(all_results)
    
    # Update global counters
    stats = db.get_statistics()
    scanned_count = stats.get('total_scanned', 0)
    potential_count = stats.get('potential_count', 0)
    dangerous_count = stats.get('dangerous_count', 0)
    total_sites = scanned_count
    
    logging.info(f"Loaded {len(scan_results)} existing scan results")
    
    # Get feedback statistics
    feedback_stats = db.get_feedback_stats()
    if feedback_stats.get('total_feedback', 0) > 0:
        accuracy = feedback_stats.get('accuracy_rate', 0)
        logging.info(f"AI Feedback Statistics: {feedback_stats['total_feedback']} total, {accuracy:.1f}% accuracy")
    
    # Check Ollama models
    try:
        ollama.list()
        logging.info("Ollama connection successful")
    except Exception as e:
        logging.warning(f"Ollama connection issue: {e}")
    
    # Start the web server
    web_config = config.get_web_config()
    logging.info(f"Starting C.A.K.R.A. scanner on {web_config['host']}:{web_config['port']}")
    
    socketio.run(
        app, 
        host=web_config['host'], 
        port=web_config['port'], 
        debug=web_config['debug']
    )
