# Network Checker AI Agent Instructions

This document provides essential context for AI agents working in this codebase.

## Project Overview

Network Checker is a web-based tool that displays local network information through a simple frontend-backend architecture:

- Frontend: Single HTML page displaying network information
- Backend: Express.js server that executes and parses Windows network commands

## Architecture

### Components

1. Frontend (`index.html`)
   - Simple web interface that fetches and displays network information
   - Communicates with backend via HTTP GET to `http://localhost:5000/network`
   - Handles loading states and error display

2. Backend (`agent.js`)
   - Express server running on port 5000
   - Executes Windows commands (`ipconfig /all`, `netsh wlan show interfaces`)
   - Parses command output using regex patterns
   - Returns structured JSON response

### Data Flow

1. Client makes GET request to `/network` endpoint
2. Server executes Windows network commands
3. Output is parsed using regex patterns in `parseIpconfig()` and `parseSSID()`
4. Structured data is returned as JSON

## Key Patterns

### Command Output Parsing

The backend uses regex patterns to extract specific network information:
```javascript
// Example pattern from agent.js
const reIPv4 = /IPv4 Address[\s.:]*([0-9.]+)(?:\([^)]+\))?/i;
```

### Error Handling

1. Frontend shows loading state and error messages
2. Backend gracefully handles missing WLAN interfaces
3. CORS is enabled for localhost development

## Development Setup

1. Install dependencies:
```bash
npm install
```

2. Start the server:
```bash
node agent.js
```

3. Access the web interface at `http://localhost:5000`

## Security Notes

- CORS is currently open for development
- Production deployment should restrict CORS origins
- Command execution is limited to specific network info commands

## Integration Points

- Backend executes Windows-specific commands (`ipconfig`, `netsh`)
- Frontend expects specific JSON structure from backend
- Port 5000 must be available for the server

## Common Tasks

### Adding New Network Information

1. Add new regex pattern in `parseIpconfig()` or create new parser
2. Update the `/network` endpoint response structure
3. Update frontend display formatting as needed