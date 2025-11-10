# C.A.K.R.A - Intelligent Content Monitoring System

C.A.K.R.A (Cerdas Antisipasi Konten Rawan dan Asusila) is an automated artificial intelligence system designed for crawling and scraping websites to detect and analyze potentially harmful or inappropriate content. The system combines web crawling capabilities with advanced AI analysis to identify negative content in text, images, and videos.

## Overview

CAKRA consists of two main components:
- **Backend (cakra-system/)**: Python-based system handling web crawling, content scraping, and AI-powered analysis
- **Frontend (cakra-web/)**: React-based web dashboard providing a user-friendly interface for monitoring, searching, and analyzing results

## How It Works

### Backend System
The backend performs the following key functions:
1. **Web Crawling**: Systematically explores websites starting from configured URLs
2. **Content Scraping**: Extracts text, images, and other media from web pages
3. **AI Analysis**: Uses machine learning models to detect negative content including:
   - Text analysis (keyword detection, semantic analysis)
   - Image recognition (visual content classification)
   - Content classification and risk assessment
4. **Data Storage**: Stores analysis results in a database for later retrieval

### Frontend Dashboard
The web dashboard provides:
- **Dashboard View**: Overview of crawling status and recent findings
- **Search Functionality**: Query and filter analyzed content
- **Detailed Analysis**: In-depth examination of specific domains or content
- **Real-time Monitoring**: Live updates on crawling progress and alerts

## Features

- Automated web crawling with configurable depth and scope
- Multi-modal content analysis (text, images, videos)
- Real-time dashboard with interactive visualizations
- Advanced search and filtering capabilities
- Configurable sensitivity levels for content detection
- Ethical content monitoring with privacy considerations

## Installation

### Prerequisites
- Python 3.8+
- Node.js 16+
- Ollama (for AI model inference)

### Backend Setup
1. Navigate to the backend directory:
   ```bash
   cd cakra-system
   ```
2. Install system dependencies (Ubuntu/Debian):
   ```bash
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
   ```
3. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Frontend Setup
1. Navigate to the web dashboard directory:
   ```bash
   cd cakra-web
   ```
2. Install Node.js dependencies:
   ```bash
   npm install
   ```

### AI Models Setup (Ollama)
For first-time setup:
```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Start Ollama service
ollama serve

# Pull required models
ollama pull claude-sonnet-4.5
ollama pull llava-phi3
ollama pull llama2:7b
```

For subsequent runs, simply use:
```bash
ollama serve
```

## Quick Start

### One-Command Startup (Recommended)
```bash
./start-cakra.sh
```
This comprehensive script starts both services with proper error checking and cleanup.

### Simple One-Liner Alternative
```bash
./run-cakra.sh
```
Minimal script that starts both services quickly.

### Manual Startup
If you prefer to start services manually:

**Terminal 1 - Backend:**
```bash
cd cakra-system
pip install -r requirements.txt
python -m cakra serve
```

**Terminal 2 - Frontend:**
```bash
cd cakra-web
npm install
npm run dev
```

### Access URLs
- **Frontend Dashboard**: http://localhost:5173
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs

## Troubleshooting

### Frontend Setup Issues

If you encounter permission errors when running `npm run dev` in the `cakra-web` directory, you may need to fix executable permissions for build tools:

1. **Vite permission denied**: If you see "Permission denied" for vite, run:
   ```bash
   chmod +x node_modules/.bin/vite
   ```

2. **Esbuild permission denied**: If esbuild fails with EACCES error, run:
   ```bash
   chmod +x node_modules/@esbuild/linux-x64/bin/esbuild
   ```

3. **Malformed vite executable**: If the vite binary appears corrupted (contains only a path instead of a script), you can recreate it by replacing the content of `node_modules/.bin/vite` with:
   ```bash
   #!/bin/sh
   basedir=$(dirname "$(echo "$0" | sed -e 's,\\,/,g')")

   case `uname` in
       *CYGWIN*|*MINGW*|*MSYS*)
           if command -v cygpath > /dev/null 2>&1; then
               basedir=`cygpath -w "$basedir"`
           fi
       ;;
   esac

   if [ -x "$basedir/node" ]; then
     exec "$basedir/node"  "$basedir/../vite/bin/vite.js" "$@"
   else 
     exec node  "$basedir/../vite/bin/vite.js" "$@"
   fi
   ```

After applying these fixes, try running `npm run dev` again.

## Usage

1. **Access Dashboard**: Open the web interface in your browser
2. **Configure Crawling**: Set target URLs and crawling parameters (if configurable)
3. **Monitor Progress**: View real-time crawling status on the dashboard
4. **Search Content**: Use the search page to find specific analyzed content
5. **Analyze Results**: Click on domains or content for detailed analysis

## Configuration

- Backend configuration files are located in `cakra-system/` directory
- Modify settings for crawling parameters, AI thresholds, and system behavior
- Adjust sensitivity levels and detection rules through the backend web interface or API
- Configure URL lists and crawling schedules as needed

## Development Workflow

Current development focuses on:
1. Core web crawler architecture and essential features
2. Technical requirements for crawling (queue management, dynamic content handling)
3. Text-based negative content detection methods
4. Visual content detection using AI and image recognition
5. User interface features (dashboard, reporting, notifications)
6. Management and configuration capabilities
7. Ethical and technical challenges in content detection
8. Benchmarking against existing solutions

## Contributing

When contributing to CAKRA development:
- Follow the established workflow for feature implementation
- Consider ethical implications of content detection
- Test changes thoroughly across both backend and frontend components
- Update documentation for any new features or configuration options
