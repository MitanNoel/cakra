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
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
app = Flask(__name__)
socketio = SocketIO(app)

@socketio.on('connect')
def handle_connect():
    pass

@socketio.on('request_initial')
def handle_request_initial():
    global scanned_count, potential_count, dangerous_count, scan_results, total_sites, is_scanning
    socketio.emit('initial_state', {
        'scanned': scanned_count,
        'potential': potential_count,
        'dangerous': dangerous_count,
        'results': scan_results,
        'total_sites': total_sites
    })
    socketio.emit('total_sites', total_sites)
    socketio.emit('scan_status', {'scanning': is_scanning})

OLLAMA_MODELS = {
    'text': 'qwen2:0.5b',
    'vision': 'moondream:1.8b',
    'judge': 'deepseek-r1:1.5b'
}
SHADOWDOOR_DOMAINS = {
    'illegal_gambling': [
        'example-gambling-site.com', 'fake-casino.net', 'illegal-betting.org'
    ],
    'pornography': [
        'adult-content-site.com', 'illegal-porn.net', 'explicit-material.org'
    ],
    'phishing': [
        'fake-bank-login.com', 'phishing-site.net', 'credential-theft.org'
    ],
    'malware': [
        'malware-host.com', 'trojan-download.net', 'ransomware-site.org'
    ]
}

VULNERABILITY_PATTERNS = {
    'outdated_software': ['wordpress', 'joomla', 'drupal'],
    'exposed_admin': ['/admin', '/wp-admin', '/administrator'],
    'weak_permissions': ['chmod 777', 'writable config'],
    'sql_injection': ['\' or 1=1', 'union select'],
    'xss_vulnerable': ['<script>', 'javascript:', 'onload='],
    'file_upload': ['upload.php', 'filemanager'],
    'default_credentials': ['admin/admin', 'root/root']
}

MALICIOUS_KEYWORDS = set([
    'casino', 'gambling', 'redirect', 'illegal', 'porn', 'drugs',
    'judi', 'jvdi', 'ju_di', 'toGel', 'tog3l', 't0gel', 'slot', 'sl0t', 's|ot',
    'gacor', 'g@cor', 'gac0r', 'taruhan', 'taruh@n', 'bet', 'b3t', 'b3tting',
    'poker', 'p0ker', 'pok3r', 'kasino', 'c@sin0', 'jackpot', 'jackp0t', 'j@ckpot',
    'bola', 'b0la', '18+', 'dewasa', 'dewas@', 'bokep', 'b0kep', 'boqep',
    'film panas', 'film p@nas', 'seks', 's3ks', 's3x', 'ml', 'm3sum', 'mesum',
    'video dewasa', 'vidio dewasa', 'cewek nakal', 'c3wek nakal', 'cwk nakal',
    'ABG nakal', 'ABG n@kal'
])

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
scanned_count = 0
potential_count = 0
dangerous_count = 0
total_sites = 0
stop_scan = False
is_scanning = False
current_scanning = []
RESULTS_FILE = 'scan_results.json'
CACHE_FILE = 'scan_cache.json'
scan_cache = {}

def load_scan_results():
    """Load scan results from file if it exists."""
    global scan_results, scanned_count, potential_count, dangerous_count, total_sites
    if os.path.exists(RESULTS_FILE):
        try:
            with open(RESULTS_FILE, 'r') as f:
                data = json.load(f)
                scan_results = data.get('results', [])
                scanned_count = data.get('scanned_count', 0)
                potential_count = data.get('potential_count', 0)
                dangerous_count = data.get('dangerous_count', 0)
                total_sites = len(set(result['url'] for result in scan_results))  # Unique URLs
        except Exception as e:
            print(f"Error loading results: {e}")
    
    # Load cache
    global scan_cache
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                scan_cache = json.load(f)
        except Exception as e:
            print(f"Error loading cache: {e}")

def save_scan_results():
    """Save scan results to file."""
    global scan_results, scanned_count, potential_count, dangerous_count
    try:
        data = {
            'results': scan_results,
            'scanned_count': scanned_count,
            'potential_count': potential_count,
            'dangerous_count': dangerous_count,
            'timestamp': time.time()
        }
        with open(RESULTS_FILE, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"Error saving results: {e}")
    
    # Save cache
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(scan_cache, f, indent=2)
    except Exception as e:
        print(f"Error saving cache: {e}")

def emit_progress():
    global scanned_count, total_sites, start_time, current_scanning
    if total_sites > 0:
        percentage = (scanned_count / total_sites) * 100
        elapsed = time.time() - start_time
        if scanned_count > 0:
            avg_time = elapsed / scanned_count
            remaining = total_sites - scanned_count
            eta = avg_time * remaining
        else:
            eta = 0
        socketio.emit('progress', {
            'percentage': round(percentage, 2),
            'eta': round(eta, 2),
            'current_scanning': current_scanning.copy(),
            'completed': scanned_count,
            'total': total_sites
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
    
    # Create a unique temporary directory for this session
    temp_dir = tempfile.mkdtemp(prefix='selenium_')
    
    options = Options()
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--disable-gpu')
    options.add_argument('--window-size=1920,1080')
    options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
    options.add_argument(f'--user-data-dir={temp_dir}')
    
    driver = None
    try:
        driver = webdriver.Chrome(options=options)
        driver.get(url)
        
        # Wait for page to load
        WebDriverWait(driver, 10).until(
            lambda d: d.execute_script('return document.readyState') == 'complete'
        )
        
        # Get rendered HTML
        html = driver.page_source
        soup = BeautifulSoup(html, 'html.parser')
        
        text_content = soup.get_text()
        images = [img['src'] for img in soup.find_all('img') if 'src' in img.attrs and img['src'].startswith('http')]
        js_scripts = [script.get_text() for script in soup.find_all('script') if script.get_text()]
        
        return {
            'text_content': text_content,
            'images': images,
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
    results = []
    for img_url in images[:5]:
        try:
            prompt = "Describe this image and check for gambling symbols, illegal content, or malicious elements."
            response = ollama.generate(model=model, prompt=prompt, images=[img_url])
            results.append(response['response'])
        except Exception as e:
            results.append(f"Error analyzing image: {str(e)}")
    return results

def judge_evidence(text_result, vision_results, url, server_info, shadowdoor_links, vulnerabilities, model):
    evidence = f"Text: {text_result}\nVision: {'; '.join(vision_results)}\nServer Info: {json.dumps(server_info)}\nShadowdoor Links: {json.dumps(shadowdoor_links)}\nVulnerabilities: {json.dumps(vulnerabilities)}"
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
    global scan_cache
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
    
    # Check cache first
    if url in scan_cache:
        cache_entry = scan_cache[url]
        cache_time = cache_entry.get('timestamp', 0)
        if time.time() - cache_time < 3600:  # Cache for 1 hour
            result = cache_entry['result']
            result['cached'] = True
            current_scanning.remove(url) if url in current_scanning else None
            return result
    
    try:
        start_time_req = time.time()
        response = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
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
        images = [img['src'] for img in soup.find_all('img') if 'src' in img.attrs and img['src'].startswith('http')]
        js_scripts = [script.get_text() for script in soup.find_all('script') if script.get_text()]
        
        # Detect anti-crawler techniques
        anti_crawler_indicators = detect_anti_crawler(response.text, js_scripts)
        
        # If content is suspiciously low or anti-crawler detected, try Selenium
        use_selenium = False
        if len(text_content.strip()) < 100 or anti_crawler_indicators:
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
        
        # AI Analysis
        text_result, new_keywords = analyze_text(text_content, OLLAMA_MODELS['text'])
        vision_results = analyze_images(images, OLLAMA_MODELS['vision'])
        
        result = {
            'url': url, 
            'text_result': text_result, 
            'vision_results': vision_results, 
            'new_keywords': new_keywords,
            'server_info': server_info,
            'shadowdoor_links': shadowdoor_links,
            'vulnerabilities': vulnerabilities
        }
        # Cache the result
        scan_cache[url] = {'result': result, 'timestamp': time.time()}
        return result
    except Exception as e:
        result = {'url': url, 'error': str(e)}
        # Cache the result
        scan_cache[url] = {'result': result, 'timestamp': time.time()}
        return result
    finally:
        current_scanning.remove(url) if url in current_scanning else None

def parallel_scan(sites, max_workers=3):
    """Scan multiple sites in parallel for analysis, then judge sequentially."""
    global scanned_count, potential_count, dangerous_count, scan_results, current_scanning, start_time, stop_scan, is_scanning
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
    
    scan_results.extend(analysis_results)
    save_scan_results()  # Save results after scan completes
    is_scanning = False
    socketio.emit('scan_status', {'scanning': False})

@app.route('/')
def home():
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>C.A.K.R.A. Control Panel</title>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.5/socket.io.js"></script>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f4; }
            .container { max-width: 1200px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
            h1 { color: #333; text-align: center; }
            form { margin-bottom: 20px; display: flex; flex-direction: column; }
            textarea { width: 100%; height: 100px; margin-bottom: 10px; padding: 10px; border: 1px solid #ccc; border-radius: 4px; }
            .form-row label { margin-right: 10px; }
            .form-row input { padding: 5px; border: 1px solid #ccc; border-radius: 4px; }
            #domainCheckboxes { display: flex; flex-wrap: wrap; gap: 10px; }
            #domainCheckboxes label { display: flex; align-items: center; margin: 0; }
            button { padding: 10px 20px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
            button:hover { background-color: #0056b3; }
            .counters { display: flex; justify-content: space-around; margin-bottom: 20px; }
            .counter { text-align: center; padding: 10px; border-radius: 4px; }
            .scanned { background-color: #17a2b8; color: white; }
            .potential { background-color: #ffc107; color: black; }
            .dangerous { background-color: #dc3545; color: white; }
            .status-summary { margin-bottom: 20px; text-align: center; font-weight: bold; }
            #filters input, #filters select { padding: 8px; border: 1px solid #ccc; border-radius: 4px; }
            table { width: 100%; border-collapse: collapse; table-layout: fixed; }
            th:nth-child(1), td:nth-child(1) { width: 25%; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; } /* URL */
            th:nth-child(2), td:nth-child(2) { width: 10%; }  /* Confidence */
            th:nth-child(3), td:nth-child(3) { width: 25%; } /* Judgment */
            th:nth-child(4), td:nth-child(4) { width: 20%; } /* Text Analysis */
            th:nth-child(5), td:nth-child(5) { width: 20%; } /* Vision Analysis */
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; word-wrap: break-word; overflow-wrap: break-word; vertical-align: top; }
            th { background-color: #f2f2f2; }
            .queued { background-color: #f8f9fa; }
            .analyzing { background-color: #cce5ff; }
            .judging { background-color: #fff3cd; }
            .safe { background-color: #d4edda; }
            .potential { background-color: #fff3cd; }
            .malicious { background-color: #f8d7da; }
            .error { background-color: #f5c6cb; }
            .url-link { color: #007bff; text-decoration: none; cursor: pointer; }
            .url-link:hover { text-decoration: underline; }
            .modal { display: none; position: fixed; z-index: 1; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.4); }
            .modal-content { background-color: #fefefe; margin: 15% auto; padding: 20px; border: 1px solid #888; width: 80%; max-width: 800px; border-radius: 8px; }
            .close { color: #aaa; float: right; font-size: 28px; font-weight: bold; cursor: pointer; }
            .close:hover { color: black; }
            .detail-section { margin-bottom: 15px; }
            .detail-label { font-weight: bold; color: #333; }
            .server-info { background-color: #f8f9fa; padding: 10px; border-radius: 4px; margin-top: 10px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>C.A.K.R.A. Control Panel</h1>
            ${SELENIUM_AVAILABLE ? '' : '<p style="color: orange;">Note: Selenium not installed. Anti-crawler detection limited to basic patterns.</p>'}
            <div class="counters">
                <div class="counter scanned" id="scanned">0 Web Scanned</div>
                <div class="counter potential" id="potential">0 Web Potential Dangerous</div>
                <div class="counter dangerous" id="dangerous">0 Web Dangerous</div>
                <div class="counter" id="found">0 Websites Found</div>
            </div>
            <div class="status-summary">
                <p id="statusSummary">Ready to scan</p>
            </div>
            <div id="progress">
                <p>Progress: <span id="percentage">0</span>% (<span id="completed">0</span>/<span id="total">0</span> sites)</p>
                <p>Estimated Time Remaining: <span id="eta">0</span> seconds</p>
                <p>Currently Scanning: <span id="current"></span></p>
                <div id="progressBar" style="width: 100%; background-color: #f0f0f0; border-radius: 5px; margin-top: 10px;">
                    <div id="progressFill" style="width: 0%; height: 20px; background-color: #007bff; border-radius: 5px; transition: width 0.3s;"></div>
                </div>
            </div>
            <form id="scanForm">
                <textarea name="urls" placeholder="https://example.com\nhttps://another.com"></textarea>
                <div class="form-row">
                    <label>Scan Indonesian Domains:</label>
                    <div id="domainCheckboxes">
                        <label><input type="checkbox" name="domains" value=".id"> .id</label>
                        <label><input type="checkbox" name="domains" value=".go.id"> .go.id</label>
                        <label><input type="checkbox" name="domains" value=".ac.id"> .ac.id</label>
                        <label><input type="checkbox" name="domains" value=".co.id"> .co.id</label>
                        <label><input type="checkbox" name="domains" value=".or.id"> .or.id</label>
                        <label><input type="checkbox" name="domains" value=".net.id"> .net.id</label>
                        <label><input type="checkbox" name="domains" value=".web.id"> .web.id</label>
                        <label><input type="checkbox" name="domains" value=".sch.id"> .sch.id</label>
                        <label><input type="checkbox" name="domains" value=".mil.id"> .mil.id</label>
                        <label><input type="checkbox" name="domains" value=".edu"> .edu</label>
                        <label><input type="checkbox" name="domains" value=".gov.id"> .gov.id</label>
                        <label><input type="checkbox" name="domains" value=".com"> .com</label>
                        <label><input type="checkbox" name="domains" value=".org"> .org</label>
                        <label><input type="checkbox" name="domains" value=".net"> .net</label>
                    </div>
                </div>
                <button type="submit" id="scanButton">Start Scan</button>
            <button type="button" id="exportButton">Export to CSV</button>
            </form>
            <div id="status"></div>
            <div id="filters">
                <input type="text" id="searchInput" placeholder="Search URLs...">
                <select id="judgmentFilter">
                    <option value="">All Judgments</option>
                    <option value="Queued">Queued</option>
                    <option value="Analyzing in Progress">Analyzing in Progress</option>
                    <option value="Judging in Progress">Judging in Progress</option>
                    <option value="Safe">Safe</option>
                    <option value="Potential">Potential</option>
                    <option value="Malicious">Malicious</option>
                    <option value="Error">Error</option>
                </select>
            </div>
            <div id="results">
                <table id="resultsTable">
                    <thead>
                        <tr>
                            <th>URL</th>
                            <th>Confidence</th>
                            <th>Judgment</th>
                            <th>Text Analysis</th>
                            <th>Vision Analysis</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                </table>
            </div>
            
            <!-- Modal for URL details -->
            <div id="urlModal" class="modal">
                <div class="modal-content">
                    <span class="close">&times;</span>
                    <h2>Website Details</h2>
                    <div id="modalContent"></div>
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
                if (data.scanning) {
                    button.textContent = 'Stop Scan';
                    statusSummary.textContent = 'Scanning in progress...';
                } else {
                    button.textContent = 'Start Scan';
                    statusSummary.textContent = 'Scan completed or stopped';
                }
            });
            
            socket.on('progress', function(data) {
                document.getElementById('percentage').textContent = data.percentage;
                document.getElementById('eta').textContent = data.eta;
                document.getElementById('current').textContent = data.current_scanning.join(', ');
                document.getElementById('progressFill').style.width = data.percentage + '%';
                document.getElementById('completed').textContent = data.completed || 0;
                document.getElementById('total').textContent = data.total || 0;
            });
            
            socket.on('total_sites', function(count) {
                document.getElementById('found').textContent = count + ' Websites Found';
                document.getElementById('total').textContent = count;
            });
            
            socket.on('reset', function() {
                scanned = 0;
                potential = 0;
                dangerous = 0;
                scannedDiv.textContent = '0 Web Scanned';
                potentialDiv.textContent = '0 Web Potential Dangerous';
                dangerousDiv.textContent = '0 Web Dangerous';
                document.getElementById('percentage').textContent = '0';
                document.getElementById('eta').textContent = '0';
                document.getElementById('current').textContent = '';
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
                        scannedDiv.textContent = scanned + ' Web Scanned';
                        // Parse judgment for counters
                        const judgment = data.judgment.toLowerCase();
                        if (judgment.includes('malicious') || judgment.includes('dangerous')) {
                            dangerous++;
                            dangerousDiv.textContent = dangerous + ' Web Dangerous';
                        } else if (judgment.includes('potential') || judgment.includes('suspicious')) {
                            potential++;
                            potentialDiv.textContent = potential + ' Web Potential Dangerous';
                        }
                    }
                    // Update row
                    existingRow.cells[1].innerHTML = data.confidence || 'N/A';
                    existingRow.cells[2].innerHTML = data.judgment;
                    // Simplify display for table
                    let textDisplay = data.judgment === 'Queued' ? 'Queued' : (data.judgment === 'Error' ? 'Error' : 'Done');
                    let visionDisplay = data.judgment === 'Queued' ? 'Queued' : (data.judgment === 'Error' ? 'Error' : 'Done');
                    existingRow.cells[3].innerHTML = textDisplay;
                    existingRow.cells[4].innerHTML = visionDisplay;
                    let rowClass = data.judgment.toLowerCase().replace(/\s+/g, '').replace('inprogress', '');
                    existingRow.className = rowClass;
                } else {
                    // Create new row
                    const row = document.createElement('tr');
                    // Simplify display for table
                    let textDisplay = data.judgment === 'Queued' ? 'Queued' : (data.judgment === 'Error' ? 'Error' : 'Done');
                    let visionDisplay = data.judgment === 'Queued' ? 'Queued' : (data.judgment === 'Error' ? 'Error' : 'Done');
                    let rowClass = data.judgment.toLowerCase().replace(/\s+/g, '').replace('inprogress', '');
                    row.className = rowClass;
                    row.innerHTML = `
                        <td><a href="#" class="url-link" data-url="${data.url}">${data.url}</a></td>
                        <td>${data.confidence || 'N/A'}</td>
                        <td>${data.judgment}</td>
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
                scannedDiv.textContent = scanned + ' Web Scanned';
                potentialDiv.textContent = potential + ' Web Potential Dangerous';
                dangerousDiv.textContent = dangerous + ' Web Dangerous';
                if (data.total_sites !== undefined) {
                    document.getElementById('found').textContent = data.total_sites + ' Websites Found';
                }
                
                // Populate table
                data.results.forEach(result => {
                    const row = document.createElement('tr');
                    // Simplify display for table
                    let textDisplay = result.judgment === 'Queued' ? 'Queued' : (result.judgment === 'Error' ? 'Error' : 'Done');
                    let visionDisplay = result.judgment === 'Queued' ? 'Queued' : (result.judgment === 'Error' ? 'Error' : 'Done');
                    let rowClass = result.judgment.toLowerCase().replace(/\s+/g, '').replace('inprogress', '');
                    row.className = rowClass;
                    row.innerHTML = `
                        <td><a href="#" class="url-link" data-url="${result.url}">${result.url}</a></td>
                        <td>${result.confidence || 'N/A'}</td>
                        <td>${result.judgment}</td>
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
                    ${serverInfoHtml}
                    ${shadowdoorHtml}
                    ${vulnerabilitiesHtml}
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
            
            document.getElementById('searchInput').addEventListener('input', filterResults);
            document.getElementById('judgmentFilter').addEventListener('change', filterResults);
            
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
        </script>
    </body>
    </html>
    """
    return render_template_string(html)

@app.route('/scan', methods=['POST'])
def scan():
    global scan_thread, scanned_count, potential_count, dangerous_count, scan_results, total_sites, stop_scan, is_scanning
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
    
    total_sites = len(unique_urls)  # Total unique sites found
    socketio.emit('total_sites', total_sites)
    
    if not new_urls:
        return jsonify({'status': 'All URLs already scanned'})
    
    scanned_count = len(scan_results)  # Start from existing count
    # Recalculate counters from existing results
    potential_count = sum(1 for result in scan_results if 'potential' in (result.get('judgment', '').lower()) or 'suspicious' in (result.get('judgment', '').lower()))
    dangerous_count = sum(1 for result in scan_results if 'malicious' in (result.get('judgment', '').lower()) or 'dangerous' in (result.get('judgment', '').lower()))
    stop_scan = False
    is_scanning = True
    socketio.emit('reset')
    socketio.emit('total_sites', total_sites)
    socketio.emit('scan_status', {'scanning': True})
    
    scan_thread = threading.Thread(target=lambda: parallel_scan(new_urls))
    scan_thread.start()
    
    return jsonify({'status': 'Scan started'})

@app.route('/export_csv')
def export_csv():
    global scan_results
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['URL', 'Judgment', 'Confidence', 'Text Result', 'Vision Result', 'Shadowdoor Links', 'Vulnerabilities', 'Error'])
    for result in scan_results:
        shadowdoor_str = ''
        if result.get('shadowdoor_links'):
            shadowdoor_str = '; '.join([f"{link['category']}: {link['url']} ({link['anchor_text']})" for link in result['shadowdoor_links']])
        
        vulnerabilities_str = ''
        if result.get('vulnerabilities'):
            vulnerabilities_str = '; '.join([f"{vuln['severity']}: {vuln['description']}" for vuln in result['vulnerabilities']])
        
        writer.writerow([
            result.get('url', ''),
            result.get('judgment', ''),
            result.get('confidence', ''),
            result.get('text_result', ''),
            '; '.join(result.get('vision_results', [])),
            shadowdoor_str,
            vulnerabilities_str,
            result.get('error', '')
        ])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode('utf-8')), 
                     mimetype='text/csv', 
                     as_attachment=True, 
                     download_name='scan_results.csv')

if __name__ == "__main__":
    load_scan_results()  # Load saved results on startup
    for model in OLLAMA_MODELS.values():
        try:
            ollama.list()
        except:
            pass
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
