# Network Checker

A web-based tool that displays local network information through a simple frontend-backend architecture. Built with Node.js and Express.js.

## Features

- Displays Wi-Fi network information
- Shows IPv4 configuration details
- Real-time network data updates
- Clean and responsive UI
- Works both locally and in production

## Tech Stack

- Frontend: HTML, CSS, JavaScript
- Backend: Node.js, Express.js
- Deployment: Vercel

## Local Development

1. Install dependencies:
```bash
npm install
```

2. Start the server:
```bash
node agent.js
```

3. Open http://localhost:5000 in your browser

## API Endpoints

### GET /network

Returns network information including:
- Current Wi-Fi SSID
- IPv4 Address
- Subnet Mask
- Default Gateway
- DHCP Server
- Lease Information

## Deployment

This project is configured for deployment on Vercel. The `vercel.json` file contains all necessary configuration.