# C.A.K.R.A - AI-Powered Cybersecurity Scanner

Cerdas Antisipasi Konten Rawan dan Asusila (C.A.K.R.A) is an automated artificial intelligence system designed to detect illegal content in Indonesia through advanced web crawling and analysis.

## Overview

C.A.K.R.A integrates cutting-edge AI models with comprehensive web analysis capabilities to identify and track illegal online activities. The system combines multi-modal content analysis, payment channel detection, and network mapping to provide actionable intelligence for law enforcement and regulatory agencies.

## Key Features

1. AI-Powered Web Crawling
   - Intelligent crawling with deep link analysis
   - Advanced suspicious content detection
   - Anti-detection mechanisms
   - Resource-optimized parallel processing

2. Multi-Modal Content Analysis
   - Text analysis using Qwen model
   - Image processing with LLaVA Phi
   - JavaScript and dynamic content analysis
   - Pattern recognition and classification

3. Payment Channel Detection
   - QRIS code identification
   - E-wallet account detection
   - Bank account pattern matching
   - Phone number correlation
   - Transaction flow mapping

4. Operator Network Mapping
   - Infrastructure correlation
   - Domain relationship analysis
   - Hosting pattern detection
   - Operator cluster identification

5. Real-time Classification
   - Gambling and illegal betting
   - Scam and fraud detection
   - Website defacement
   - Harmful content categorization
   - Confidence scoring

6. Intelligence Reporting
   - Detailed analysis reports
   - Evidence documentation
   - Risk assessment metrics
   - Actionable recommendations

7. Integration API
   - RESTful endpoints
   - Real-time data access
   - Government agency integration
   - ISP coordination support

## Installation

### System Dependencies

For Ubuntu/Debian systems, install required system libraries:

```bash
# Install system dependencies for Playwright browser automation
sudo apt-get install -y \
    libatk1.0-0t64 \
    libatk-bridge2.0-0t64 \
    libcups2t64 \
    libxkbcommon0 \
    libatspi2.0-0t64 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2t64

# Set up swap space (if system memory is less than 16GB)
if [ "$(free -g | awk '/^Mem:/{print $2}')" -lt 16 ]; then
    echo "Setting up swap space for large language models..."
    sudo fallocate -l 8G /swapfile
    sudo chmod 600 /swapfile
    sudo mkswap /swapfile
    sudo swapon /swapfile
    # Make swap persistent
    echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
fi
```

### Python Dependencies

```bash
pip install -r requirements.txt

# Install and Start Ollama
curl -fsSL https://ollama.ai/install.sh | sh
sudo systemctl start ollama  # Start Ollama as a system service

# Or start manually in a separate terminal:
# ollama serve

# Pull required AI models
ollama pull qwen2:7b
ollama pull llava-phi3
ollama pull llama2:7b

# Install Required AI Models
ollama pull qwen2:7b
ollama pull llava-phi3
ollama pull llama2:7b
```

## Usage

The C.A.K.R.A system offers multiple interfaces for different use cases:

### Command Line Interface

Launch the CLI application:
```bash
python -m cakra scan <url>
```

Core CLI Features:
1. URL Scanning and Analysis
2. Batch Processing Workflows
3. Intelligence Report Generation
4. System Statistics and Monitoring

### Web Interface and API Server

Start the web server:
```bash
python -m cakra serve
```

Access Points:
- Web Dashboard: http://localhost:5000
- API Endpoints: http://localhost:5000/api/v1
- API Documentation: http://localhost:5000/docs

### Development Server

For development and testing:
```bash
python -m cakra serve --debug
```

## API Reference

C.A.K.R.A provides a comprehensive RESTful API for integration with external systems.

### Core Endpoints

1. System Status
```http
GET /api/v1/health
```

2. Scan Operations
```http
GET /api/v1/scan-results
POST /api/v1/scan
POST /api/v1/bulk-scan
GET /api/v1/scan-results/{url}
```

Parameters for GET /api/v1/scan-results:
- limit: Maximum results (default: 100, max: 1000)
- offset: Pagination offset (default: 0)
- min_illegal_rate: Minimum illegal rate 0-100 (default: 0)
- max_illegal_rate: Maximum illegal rate 0-100 (default: 100)
- classification: Filter by classification
- days_back: Results from last N days (default: 30)

3. Intelligence Data
```http
GET /api/v1/payment-channels
GET /api/v1/operator-clusters
GET /api/v1/link-networks
GET /api/v1/intelligence-reports
POST /api/v1/intelligence-reports/generate
```

Parameters for GET /api/v1/payment-channels:
- limit: Maximum results (default: 500, max: 2000)
- type: Channel type (qris, e-wallet, bank_account, phone_number)
- min_risk_score: Minimum risk score (default: 0)

### Request Examples

1. Submit URL for Scanning
```http
POST /api/v1/scan
Content-Type: application/json

{
    "url": "https://example.com",
    "priority": "high"
}
```

2. Bulk Scanning Operation
```http
POST /api/v1/bulk-scan
Content-Type: application/json

{
    "urls": [
        "https://site1.com",
        "https://site2.com"
    ],
    "keywords": ["gambling", "casino"],
    "base_domains": [".id", ".com"]
}
```

3. Enhanced AI Analysis
```http
POST /api/v1/enhanced-scan
Content-Type: application/json

{
    "seed_urls": ["https://example.com"],
    "keywords": ["judi", "togel", "casino"],
    "base_domains": [".id", ".com", ".net"]
}
```

For detailed API documentation including response formats and error codes, visit the `/docs` endpoint after starting the server.

## System Architecture

The C.A.K.R.A system employs a modular, pipeline-based architecture for efficient processing:

1. Scout Agent (Web Crawler)
   - Based on Playwright
   - Handles raw HTML and screenshots
   - Anti-detection capabilities
   - Resource-aware scheduling

2. Analysis Agents
   - Text Analysis: Qwen Model
   - Visual Analysis: LLaVA Phi
   - Content Classification
   - Pattern Detection

3. Payment Investigation
   - Tesseract OCR Engine
   - Regular Expression Patterns
   - Payment Channel Correlation
   - Risk Assessment

4. Network Analysis
   - NetworkX Graph Analysis
   - Infrastructure Mapping
   - Domain Correlation
   - Cluster Detection

5. Evidence Processing
   - LLaMa 2 7B Evaluation
   - Rule-based Scoring
   - Severity Assessment
   - Confidence Rating

6. Report Generation
   - LLaMa 2 7B Synthesis
   - Structured Output
   - Evidence Documentation
   - Action Recommendations

## Configuration

System configuration is managed through config.yaml with the following sections:

1. Database Settings
   - Connection parameters
   - Pool configuration
   - Cache settings
   - Backup options

2. AI Model Configuration
   - Model selection
   - Batch processing
   - Resource allocation
   - Temperature settings

3. Scanning Parameters
   - Crawl depth
   - Request timing
   - Pattern matching
   - Domain filters

4. Intelligence Options
   - Network analysis depth
   - Risk thresholds
   - Cluster parameters
   - Report formats

## Performance Notes

Environment Requirements:
- CPU: 4 cores minimum
- RAM: 16GB recommended
- Storage: SSD preferred
- Network: Stable connection required

Tested and optimized for cloud deployment with resource-aware scheduling and efficient memory management.


Missing Steps :

python -m playwright install
python -m playwright install-deps
sudo apt update && sudo apt install -y tesseract-ocr