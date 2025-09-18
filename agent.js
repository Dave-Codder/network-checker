// agent.js
const { exec } = require("child_process");

// Sample data for Vercel deployment since we can't run Windows commands
const sampleData = {
  ipv4: "192.168.1.100",
  subnetMask: "255.255.255.0",
  defaultGateway: "192.168.1.1",
  dhcpServer: "192.168.1.1",
  ssid: "Sample-Network",
  leaseObtained: "September 18, 2025 10:00:00 AM",
  leaseExpires: "September 19, 2025 10:00:00 AM"
};

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

module.exports = async (req, res) => {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET');
  
  if (process.env.VERCEL) {
    // When running on Vercel, return sample data
    res.json(sampleData);
    return;
  }

  // For local development, use actual system commands
  try {
    const [netshStdout, ipStdout] = await Promise.all([
      new Promise((resolve) => {
        exec("netsh wlan show interfaces", (err, stdout) => {
          resolve(err ? "" : stdout);
        });
      }),
      new Promise((resolve, reject) => {
        exec("ipconfig /all", (err, stdout) => {
          if (err) reject(new Error("Failed to run ipconfig"));
          resolve(stdout);
        });
      })
    ]);

    const ssid = parseSSID(netshStdout);
    const ip = parseIpconfig(ipStdout);
    res.json({ ssid, ...ip });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};
