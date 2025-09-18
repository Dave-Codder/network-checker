// agent.js
const express = require("express");
const { exec } = require("child_process");
const cors = require("cors");
const os = require("os");

const app = express();
app.use(cors());

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

// Get network interfaces information using 'os' module
function getNetworkInterfaces() {
  const interfaces = os.networkInterfaces();
  const results = [];
  
  for (const [name, addrs] of Object.entries(interfaces)) {
    for (const addr of addrs) {
      if (addr.family === 'IPv4' && !addr.internal) {
        results.push({
          interface: name,
          ipv4: addr.address,
          subnetMask: addr.netmask,
          mac: addr.mac
        });
      }
    }
  }
  return results;
}

app.get("/network", async (req, res) => {
  try {
    // Get client's IP address
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    
    // Get all network interfaces
    const networkInterfaces = getNetworkInterfaces();
    
    let networkData = {
      clientIp: clientIp,
      interfaces: networkInterfaces,
      timestamp: new Date().toISOString()
    };

    // If on Windows, try to get additional network information
    if (process.platform === 'win32') {
      try {
        const [netshStdout, ipStdout] = await Promise.all([
          new Promise((resolve) => {
            exec("netsh wlan show interfaces", (err, stdout) => {
              resolve(err ? "" : stdout);
            });
          }),
          new Promise((resolve) => {
            exec("ipconfig /all", (err, stdout) => {
              resolve(err ? "" : stdout);
            });
          })
        ]);

        const ssid = parseSSID(netshStdout);
        const ipConfig = parseIpconfig(ipStdout);
        
        networkData = {
          ...networkData,
          ssid,
          ...ipConfig
        };
      } catch (err) {
        console.error('Windows-specific command error:', err);
      }
    }

    res.json(networkData);
  } catch (error) {
    res.status(500).json({ 
      error: "Failed to get network information",
      message: error.message 
    });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Network agent running at http://localhost:${PORT}/network`);
});
