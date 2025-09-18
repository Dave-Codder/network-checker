const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

// CORS wrapper
const allowCors = fn => async (req, res) => {
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, X-Client-IP'
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
  const reDhcpV6Iaid = /DHCPv6 IAID[\s.:]*([0-9]+)/i;
  const reDhcpV6Duid = /DHCPv6 Client DUID[\s.:]*([^\r\n]+)/i;
  const reDnsServers = /DNS Servers[\s.:]*([^\r\n]+)/i;
  const reConnSuffix = /Connection-specific DNS Suffix[\s.:]*([^\r\n]+)/i;

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

  // DHCPv6 IAID
  const mIaid = output.match(reDhcpV6Iaid);
  if (mIaid) result.dhcpv6Iaid = mIaid[1].trim();
  // DHCPv6 Client DUID
  const mDuid = output.match(reDhcpV6Duid);
  if (mDuid) result.dhcpv6ClientDuid = mDuid[1].trim();

  // DNS Servers: can be on multiple lines indented under the DNS Servers line
  const mDns = output.match(reDnsServers);
  if (mDns) {
    const first = mDns[1].trim();
    const dnsList = [first];
    // look for subsequent indented DNS entries directly following the match
    const after = output.slice(output.indexOf(mDns[0]) + mDns[0].length);
    const lines = after.split(/\r?\n/);
    for (const ln of lines) {
      const trimmed = ln.trim();
      if (!trimmed) break;
      // lines that start with a digit are additional servers
      if (/^[0-9]/.test(trimmed)) dnsList.push(trimmed.split(/\s+/)[0]);
      else break;
    }
    result.dnsServers = dnsList;
  }

  // Connection-specific DNS Suffix
  const mSuffix = output.match(reConnSuffix);
  if (mSuffix) result.connectionSpecificDnsSuffix = mSuffix[1].trim();

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
    // In production (Vercel or other non-Windows), prefer client-provided local IP
    if (process.platform !== 'win32') {
      // Allow clients to POST their `ipconfig` and `netsh` raw outputs to get identical parsing as local
      let clientIpconfig = null;
      let clientNetsh = null;
      try {
        if (req.method === 'POST') {
          // support both JSON and plain text
          if (req.headers['content-type'] && req.headers['content-type'].includes('application/json')) {
            const body = await new Promise((resolve) => {
              let data = '';
              req.on('data', chunk => data += chunk);
              req.on('end', () => resolve(JSON.parse(data)));
            });
            clientIpconfig = body.ipconfig || null;
            clientNetsh = body.netsh || null;
          } else {
            const text = await new Promise((resolve) => {
              let data = '';
              req.on('data', chunk => data += chunk);
              req.on('end', () => resolve(data));
            });
            // attempt to heuristically split if both provided
            if (text.includes('Windows IP Configuration') || text.includes('IPv4')) clientIpconfig = text;
            else clientNetsh = text;
          }
        }

      } catch (e) {
        console.warn('Failed to parse POST body:', e.message);
      }

      const rawIp = (req.headers['x-client-ip'] || req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.socket.remoteAddress || '').split(',')[0].trim();
      const ipv4Regex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
      const isIpv4 = ipv4Regex.test(rawIp) && rawIp.split('.').every(n => Number(n) >= 0 && Number(n) <= 255);

      let ipv4 = null;
      let subnetMask = null;
      let defaultGateway = null;
      let dhcpServer = null;
  let dnsServers = null;
  let connectionSpecificDnsSuffix = null;
  let dhcpv6Iaid = null;
  let dhcpv6ClientDuid = null;

      // If the client POSTed ipconfig /all or netsh outputs, parse and return those results
      if (clientIpconfig) {
        const parsed = parseIpconfig(clientIpconfig);
        const ssid = clientNetsh ? parseSSID(clientNetsh) : null;
        return res.status(200).json({
          ssid: ssid || null,
          ipv4: parsed.ipv4 || null,
          subnetMask: parsed.subnetMask || null,
          leaseObtained: parsed.leaseObtained || null,
          leaseExpires: parsed.leaseExpires || null,
          defaultGateway: parsed.defaultGateway || null,
          dhcpServer: parsed.dhcpServer || null,
          dnsServers: parsed.dnsServers || null,
          connectionSpecificDnsSuffix: parsed.connectionSpecificDnsSuffix || null,
          dhcpv6Iaid: parsed.dhcpv6Iaid || null,
          dhcpv6ClientDuid: parsed.dhcpv6ClientDuid || null,
          timestamp: new Date().toISOString(),
          note: 'Client-provided ipconfig/netsh parsed in cloud'
        });
      }

      // If no client raw dump, fall back to best-effort derivation from supplied IP header
      if (isIpv4) {
        ipv4 = rawIp;
        subnetMask = '255.255.255.0';
        const parts = ipv4.split('.');
        defaultGateway = `${parts[0]}.${parts[1]}.${parts[2]}.1`;
        // do not assume DHCP server equals gateway; leave dhcpServer null unless provided
      }

      return res.status(200).json({
        ssid: null,
        ipv4,
        subnetMask,
        leaseObtained: null,
        leaseExpires: null,
        defaultGateway,
        dhcpServer,
        dnsServers,
        connectionSpecificDnsSuffix,
        dhcpv6Iaid,
        dhcpv6ClientDuid,
        timestamp: new Date().toISOString(),
        note: isIpv4 ? 'Client-supplied local network info used in cloud environment (derived values)' : 'No valid client IPv4 provided'
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
      ipv4: ipInfo.ipv4 || null,
      subnetMask: ipInfo.subnetMask || null,
      defaultGateway: ipInfo.defaultGateway || null,
      dhcpServer: ipInfo.dhcpServer || null,
      dnsServers: ipInfo.dnsServers || null,
      connectionSpecificDnsSuffix: ipInfo.connectionSpecificDnsSuffix || null,
      dhcpv6Iaid: ipInfo.dhcpv6Iaid || null,
      dhcpv6ClientDuid: ipInfo.dhcpv6ClientDuid || null,
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