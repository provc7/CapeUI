# CapeUI

A comprehensive web interface for submitting and analyzing malware using the CAPE sandbox API, enriched with advanced querying, reporting, and AI assistance.

## Features

- **Modern Web Interface**: Intuitive UI (`index.html`) for submitting files (EXE, DLL, ZIP, APK, Office, PDF, etc.) to CAPE.
- **Submission History**: Persistent tracking of user submissions via MongoDB.
- **Analysis Dashboard**: Dedicated view (`analysis.html`) for in-depth analysis of task reports, signatures, and IOCs.
- **Visualizer**: Advanced JSON report visualizer (`visualiser.html`) to navigate complex analysis data interactively.
- **Super Admin Dashboard**: Administrative panel (`superadmin.html`) to manage users, track site-wide submission statistics, and inspect Elasticsearch reports.
- **Elasticsearch Integration**: Robust indexing of analysis reports for fast searching and statistical aggregation.
- **CyberHelp Chatbot**: Integrated AI assistant utilizing Hugging Face Inference API for malware analysis guidance and queries.
- **Malware Bazaar Integration**: Direct health checks and potential sample submissions.

## Installation

1. Install Node.js
2. Install dependencies:
   ```bash
   npm install
   ```
3. Configure the environment by creating a `.env` file based on `.env.example` or following the variables below:
   ```env
   MONGODB_URI=your_mongodb_connection_string
   JWT_SECRET=your_jwt_secret
   PORT=3000
   HOST=0.0.0.0
   CAPE_API_BASE=http://your_cape_ip:8000
   CAPE_EXPLORER_HOST=0.0.0.0
   CAPE_EXPLORER_PORT=9000
   ADMIN_USERNAME=root
   ADMIN_PASSWORD=your_admin_password
   STUDENT_PASSWORD=your_default_student_password
   ABUSE_CH_API_KEY=your_abuse_ch_api_key
   ELASTICSEARCH_NODE=http://localhost:9200
   ELASTICSEARCH_INDEX=student
   ELASTICSEARCH_USERNAME=elastic
   ELASTICSEARCH_PASSWORD=your_es_password
   HF_API_TOKEN=your_huggingface_token
   HF_MODEL=meta-llama/Llama-3.1-8B-Instruct
   HF_API_URL=https://router.huggingface.co/v1/chat/completions
   ```

## Usage

1. Start the server:
   ```bash
   npm start
   ```
   Or for development with auto-reload:
   ```bash
   npm run dev
   ```
2. Navigate to `http://localhost:3000`
3. **Roles and Access**:
   - **Users/Students**: Can submit files, view their own submission history, and analyze results.

## Architecture

- **Frontend**: Vanilla HTML/JS/CSS focusing on dynamic UI updates without heavy frameworks.
- **Backend Proxy**: Express.js server (`server.js`) securely routes requests to the CAPE Sandbox, Elasticsearch, and Hugging Face API to circumvent CORS and protect API keys.
- **Database**: MongoDB handles user authentication, submission logs, and session management. Elasticsearch processes large analysis payloads for querying.

## Core API Endpoints

- `POST /api/upload`: Upload file to CAPE sandbox
- `GET /api/submissions`: Retrieve user submission history
- `GET /api/task/:taskId`: Get task status
- `GET /api/task/:taskId/report`: Retrieve full CAPE analysis report
- `POST /api/chatbot`: Interact with the AI assistant
- `POST /api/malware-bazaar`: Query Malware Bazaar

## File Structure

```
.
├── index.html               # Main user submission interface
├── analysis.html            # Detailed analysis report view
├── visualiser.html          # Interactive JSON report visualizer
├── server.js                # Core Node.js backend
├── cape_reports_explorer.py # Python helper server for report exploration
├── check_*.js               # Utility scripts for database and sanity checks
├── .env                     # Configuration file
└── package.json             # Dependencies
```
