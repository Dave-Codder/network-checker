// agent.js
const express = require('express');
const { exec } = require('child_process');
const cors = require('cors');

const app = express();
app.use(cors()); // boleh diakses dari frontend

// Serve static files from current directory
app.use(express.static(__dirname));

// Serve index.html at root path
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/index.html');
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

  exec('netsh wlan show interfaces', (err, netshStdout) => {
    if (err) netshStdout = '';
    exec('ipconfig /all', (err2, ipStdout) => {
      if (err2) {
        res.status(500).json({ error: 'Gagal menjalankan ipconfig' });
        return;
      }
      const ssid = parseSSID(netshStdout);
      const ip = parseIpconfig(ipStdout);
      res.json({ ssid, ...ip });
    });
  });
});

// 🔹 Jalankan server di port 5000
const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`✅ Network agent running at http://localhost:${PORT}/network`)
);
// });
