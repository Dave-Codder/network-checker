// agent.js
const express = require('express');
const { exec } = require('child_process');
const cors = require('cors');

const app = express();

// Configure CORS for development
app.use(cors({
  origin: ['http://localhost:5000', 'http://127.0.0.1:5000'],
  methods: ['GET'],
  allowedHeaders: ['Accept', 'Content-Type', 'X-Client-IP', 'X-Network-SSID', 'X-Network-Type', 
    'X-Network-SubnetMask', 'X-Network-Gateway', 'X-Network-ID', 'X-Network-Signal', 
    'X-Network-Speed', 'X-Network-All-IPs', 'Cache-Control']
}));

// Serve static files from current directory
app.use(express.static(__dirname));

// Serve index.html at root path
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/index.html');
});

// Add API endpoint alias
app.get('/api/network', (req, res) => {
  res.redirect('/network');
});

function parseIpconfig(output) {
  // ambil IPv4, Subnet Mask, Lease Obtained/Expires, Default Gateway, DHCP Server
  const result = {};
  const reIPv4 = /IPv4 Address[\s.:]*([0-9.]+)(?:\([^)]+\))?/i;
  const reMask = /Subnet Mask[\s.:]*([0-9.]+)/i;
  const reLeaseObt = /Lease Obtained[\s.:]*([^\r\n]+)/i;
  const reLeaseExp = /Lease Expires[\s.:]*([^\r\n]+)/i;
  const reGateway = /Default Gateway[\s.:]*([0-9.]+)/i;
  const reDhcp = /DHCP Server[\s.:]*([0-9.]+)/i;

  const mIPv4 = output.match(reIPv4);
  if (mIPv4) result.ipv4 = mIPv4[1].trim();
  const mMask = output.match(reMask);
  if (mMask) result.subnetMask = mMask[1].trim();
  const mObt = output.match(reLeaseObt);
  if (mObt) result.leaseObtained = mObt[1].trim();
  const mExp = output.match(reLeaseExp);
  if (mExp) result.leaseExpires = mExp[1].trim();
  const mGW = output.match(reGateway);
  if (mGW) result.defaultGateway = mGW[1].trim();
  const mDhcp = output.match(reDhcp);
  if (mDhcp) result.dhcpServer = mDhcp[1].trim();

  return result;
}

function parseSSID(netshOutput) {
  // dari "netsh wlan show interfaces"
  const reSSID = /^\s*SSID\s*:\s*(.+)$/m;
  const m = netshOutput.match(reSSID);
  if (m) return m[1].trim();
  return null;
}

// 🔹 Endpoint utama
app.get('/network', (req, res) => {
  // Set proper content type header
  res.setHeader('Content-Type', 'application/json');

  // Untuk Vercel deployment, berikan pesan khusus
  if (process.env.VERCEL) {
    res.json({
      message: "This feature requires running on a local machine to access network information"
    });
    return;
  }

  // Get client IP from headers if available
  const clientIP = req.headers['x-client-ip'];
  const clientNetworkInfo = {
    ssid: req.headers['x-network-ssid'],
    type: req.headers['x-network-type'],
    subnetMask: req.headers['x-network-subnetmask'],
    defaultGateway: req.headers['x-network-gateway'],
    networkId: req.headers['x-network-id'],
    signalStrength: req.headers['x-network-signal'],
    networkSpeed: req.headers['x-network-speed']
  };

  // Clean undefined values
  Object.keys(clientNetworkInfo).forEach(key => 
    clientNetworkInfo[key] === undefined && delete clientNetworkInfo[key]
  );

  exec('netsh wlan show interfaces', (err, netshStdout) => {
    // Don't treat WLAN error as fatal
    if (err) {
      console.warn('WLAN info not available:', err.message);
      netshStdout = '';
    }

    exec('ipconfig /all', (err2, ipStdout) => {
      if (err2) {
        console.error('Failed to get network info:', err2);
        res.status(500).json({ 
          error: 'Failed to get network information',
          details: err2.message,
          clientInfo: clientNetworkInfo 
        });
        return;
      }

      try {
        const ssid = parseSSID(netshStdout);
        const ip = parseIpconfig(ipStdout);

        // Combine client-side and server-side info
        const result = {
          ...clientNetworkInfo,
          ...ip,
          timestamp: new Date().toISOString()
        };

        // Only set SSID if we found one server-side or got one from client
        if (ssid || clientNetworkInfo.ssid) {
          result.ssid = ssid || clientNetworkInfo.ssid;
        }

        res.json(result);
      } catch (e) {
        console.error('Error parsing network info:', e);
        res.status(500).json({ 
          error: 'Failed to parse network information',
          details: e.message,
          clientInfo: clientNetworkInfo
        });
      }
    });
  });
});

// 🔹 Jalankan server di port 5000
const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`✅ Network agent running at http://localhost:${PORT}/network`)
);
// });
