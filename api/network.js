const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

// CORS wrapper
const allowCors = fn => async (req, res) => {
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
  );
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }
  return await fn(req, res);
};

// Parsing functions
function parseIpconfig(output) {
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
  const reSSID = /^\s*SSID\s*:\s*(.+)$/m;
  const m = netshOutput.match(reSSID);
  if (m) return m[1].trim();
  return null;
}

const handler = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET');
  res.setHeader('Content-Type', 'application/json');

  try {
    // Check if running on Windows
    if (process.platform !== 'win32') {
      return res.status(400).json({
        error: 'Platform not supported',
        message: 'This application requires Windows to get network information'
      });
    }

    // Execute both commands
    let netshOutput = '';
    let ipOutput = '';

    try {
      const { stdout: netshStdout } = await execAsync('netsh wlan show interfaces');
      netshOutput = netshStdout;
    } catch (err) {
      console.warn('WLAN information not available:', err.message);
      // Don't throw, continue without WLAN info
    }

    let ipInfo = {};
    try {
      const { stdout: ipStdout } = await execAsync('ipconfig /all');
      ipOutput = ipStdout;
      ipInfo = parseIpconfig(ipOutput);
    } catch (err) {
      console.error('Failed to get IP configuration:', err.message);
      return res.status(500).json({
        error: 'Command execution failed',
        message: 'Failed to get network information',
        details: err.message
      });
    }

    // Ensure we have at least some data
    if (!ipInfo.ipv4) {
      return res.status(404).json({
        error: 'No data',
        message: 'No network adapter information found'
      });
    }

    // Parse and combine the results
    const networkInfo = {
      ssid: parseSSID(netshOutput) || null,
      ipAddress: ipInfo.ipv4 || null,
      subnetMask: ipInfo.subnetMask || null,
      defaultGateway: ipInfo.defaultGateway || null,
      dhcpServer: ipInfo.dhcpServer || null,
      leaseObtained: ipInfo.leaseObtained || null,
      leaseExpires: ipInfo.leaseExpires || null,
      timestamp: new Date().toISOString()
    };

    res.status(200).json(networkInfo);
  } catch (error) {
    res.status(500).json({
      error: "Failed to get network information",
      message: error.message
    });
  }
};

module.exports = allowCors(handler);