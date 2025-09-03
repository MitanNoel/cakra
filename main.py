import ollama
import requests
from bs4 import BeautifulSoup
from flask import Flask, request, render_template_string, jsonify
from flask_socketio import SocketIO, emit
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import threading
import re
import time
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
scan_results = []
scan_thread = None
scanned_count = 0
potential_count = 0
dangerous_count = 0
total_sites = 0
stop_scan = False
is_scanning = False
current_scanning = []

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
            'current_scanning': current_scanning.copy()
        })

def google_dork_search(keywords, domains):
    """Perform web search using DuckDuckGo for unlimited free results."""
    try:
        from ddgs import DDGS
    except ImportError:
        print("ddgs not installed, using mock")
        mock_urls = []
        for domain in domains:
            for kw in keywords[:5]:
                for i in range(20):
                    mock_urls.append(f'https://sub{i}{domain}')
        return mock_urls[:200]
    
    urls = set()
    with DDGS() as ddgs:
        for domain in domains:
            for keyword in keywords[:5]:
                query = f"site:{domain} {keyword}"
                try:
                    results = list(ddgs.text(query, max_results=20))
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

def judge_evidence(text_result, vision_results, url, model):
    evidence = f"Text: {text_result}\nVision: {'; '.join(vision_results)}"
    prompt = f"Based on evidence from text and vision analysis of {url}, provide a structured judgment:\n- Confidence Score (0-100, where 0 is very safe and 100 is very dangerous)\n- Detailed Result (malicious/safe)\n- Website Weaknesses\n- Shadowdoor/Defacement Detection\n- Domain/IP Address\n- Recommendations"
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
    try:
        response = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
        soup = BeautifulSoup(response.text, 'html.parser')
        text_content = soup.get_text()
        images = [img['src'] for img in soup.find_all('img') if 'src' in img.attrs and img['src'].startswith('http')]
        
        # AI Analysis
        text_result, new_keywords = analyze_text(text_content, OLLAMA_MODELS['text'])
        vision_results = analyze_images(images, OLLAMA_MODELS['vision'])
        
        return {'url': url, 'text_result': text_result, 'vision_results': vision_results, 'new_keywords': new_keywords}
    except Exception as e:
        return {'url': url, 'error': str(e)}
    finally:
        current_scanning.remove(url) if url in current_scanning else None

def parallel_scan(sites, max_workers=3):
    """Scan multiple sites in parallel for analysis, then judge sequentially."""
    global scanned_count, potential_count, dangerous_count, scan_results, current_scanning, start_time, stop_scan, is_scanning
    analysis_results = []
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_site, site): site for site in sites}
        for future in as_completed(futures):
            if stop_scan:
                break
            site = futures[future]
            current_scanning.remove(site) if site in current_scanning else None
            result = future.result()
            analysis_results.append(result)
            scanned_count += 1
            
            # Emit partial update (analysis done, pending judgment)
            if 'error' in result:
                emit_data = {'url': result['url'], 'judgment': 'Error', 'text_result': '', 'vision_results': [], 'error': result['error']}
            else:
                emit_data = {'url': result['url'], 'judgment': 'Analyzed - Pending Judgment', 'text_result': result['text_result'], 'vision_results': result['vision_results']}
            socketio.emit('scan_update', emit_data)
            emit_progress()
    
    # Now judge sequentially
    for result in analysis_results:
        if stop_scan:
            break
        if 'error' not in result:
            final_judgment, confidence = judge_evidence(result['text_result'], result['vision_results'], result['url'], OLLAMA_MODELS['judge'])
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
            emit_data = {'url': result['url'], 'judgment': final_judgment, 'confidence': confidence, 'text_result': result['text_result'], 'vision_results': result['vision_results']}
            socketio.emit('scan_update', emit_data)
    
    scan_results.extend(analysis_results)
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
            #results { margin-top: 20px; }
            table { width: 100%; border-collapse: collapse; table-layout: fixed; }
            th:nth-child(1), td:nth-child(1) { width: 20%; } /* URL */
            th:nth-child(2), td:nth-child(2) { width: 8%; }  /* Confidence */
            th:nth-child(3), td:nth-child(3) { width: 25%; } /* Judgment */
            th:nth-child(4), td:nth-child(4) { width: 20%; } /* Text Analysis */
            th:nth-child(5), td:nth-child(5) { width: 15%; } /* Vision Analysis */
            th:nth-child(6), td:nth-child(6) { width: 12%; } /* Error */
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; word-wrap: break-word; overflow-wrap: break-word; vertical-align: top; }
            th { background-color: #f2f2f2; }
            .error { color: red; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>C.A.K.R.A. Control Panel</h1>
            <div class="counters">
                <div class="counter scanned" id="scanned">0 Web Scanned</div>
                <div class="counter potential" id="potential">0 Web Potential Dangerous</div>
                <div class="counter dangerous" id="dangerous">0 Web Dangerous</div>
                <div class="counter" id="found">0 Websites Found</div>
            </div>
            <div id="progress">
                <p>Progress: <span id="percentage">0</span>%</p>
                <p>Estimated Time Remaining: <span id="eta">0</span> seconds</p>
                <p>Currently Scanning: <span id="current"></span></p>
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
                    </div>
                </div>
                <button type="submit" id="scanButton">Start Scan</button>
            </form>
            <div id="status"></div>
            <div id="results">
                <table id="resultsTable">
                    <thead>
                        <tr>
                            <th>URL</th>
                            <th>Confidence</th>
                            <th>Judgment</th>
                            <th>Text Analysis</th>
                            <th>Vision Analysis</th>
                            <th>Error</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                </table>
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
            
            socket.on('connect', function() {
                socket.emit('request_initial');
            });
            
            socket.on('scan_status', function(data) {
                const button = document.getElementById('scanButton');
                if (data.scanning) {
                    button.textContent = 'Stop Scan';
                } else {
                    button.textContent = 'Start Scan';
                }
            });
            
            socket.on('progress', function(data) {
                document.getElementById('percentage').textContent = data.percentage;
                document.getElementById('eta').textContent = data.eta;
                document.getElementById('current').textContent = data.current_scanning.join(', ');
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
            });
            
            socket.on('scan_update', function(data) {
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
                
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${data.url}</td>
                    <td>${data.confidence || 'N/A'}</td>
                    <td>${data.judgment}</td>
                    <td>${data.text_result || ''}</td>
                    <td>${data.vision_results ? data.vision_results.join('<br>') : ''}</td>
                    <td class="error">${data.error || ''}</td>
                `;
                resultsTable.appendChild(row);
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
                    row.innerHTML = `
                        <td>${result.url}</td>
                        <td>${result.confidence || 'N/A'}</td>
                        <td>${result.judgment}</td>
                        <td>${result.text_result || ''}</td>
                        <td>${result.vision_results ? result.vision_results.join('<br>') : ''}</td>
                        <td class="error">${result.error || ''}</td>
                    `;
                    resultsTable.appendChild(row);
                });
            });
            
            document.getElementById('scanForm').addEventListener('submit', function(e) {
                e.preventDefault();
                // Reset counters
                scanned = 0; potential = 0; dangerous = 0;
                scannedDiv.textContent = '0 Web Scanned';
                potentialDiv.textContent = '0 Web Potential Dangerous';
                dangerousDiv.textContent = '0 Web Dangerous';
                // Clear table
                resultsTable.innerHTML = '';
                const formData = new FormData(this);
                fetch('/scan', {
                    method: 'POST',
                    body: formData
                }).then(response => response.json()).then(data => {
                    statusDiv.textContent = data.status;
                });
            });
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
    
    total_sites = len(urls)
    socketio.emit('total_sites', total_sites)
    
    scanned_count = 0
    potential_count = 0
    dangerous_count = 0
    scan_results = []
    stop_scan = False
    is_scanning = True
    socketio.emit('reset')
    socketio.emit('total_sites', total_sites)
    socketio.emit('scan_status', {'scanning': True})
    
    scan_thread = threading.Thread(target=lambda: parallel_scan(urls))
    scan_thread.start()
    
    return jsonify({'status': 'Scan started'})

@app.route('/status')
def status():
    return jsonify({'results': scan_results, 'scanning': scan_thread.is_alive() if scan_thread else False})

if __name__ == "__main__":
    for model in OLLAMA_MODELS.values():
        try:
            ollama.list()
        except:
            pass
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
