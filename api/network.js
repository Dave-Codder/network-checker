const { createClient } = require('@supabase/supabase-js');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

// Initialize Supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseAnonKey);

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
  const reIPv4 = /IPv4 Address[\s.:]*([0-9.]+)(?:[^)]+)?/i;
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
    let networkInfo;

    // In production (Vercel or other non-Windows), use enhanced client network info
    if (process.platform !== 'win32') {
      // Get network info from headers and query params
      const clientInfo = {};
      const ipv4Regex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
      const rawIp = (req.headers['x-client-ip'] || req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || '').split(',')[0].trim();
      const isIpv4 = ipv4Regex.test(rawIp) && rawIp.split('.').every(n => Number(n) >= 0 && Number(n) <= 255);
      
      // Parse additional network info from headers
      try {
        Object.keys(req.headers).forEach(key => {
          if (key.toLowerCase().startsWith('x-network-')) {
            const infoKey = key.slice('x-network-'.length).toLowerCase();
            clientInfo[infoKey] = req.headers[key];
          }
        });
      } catch (e) {
        console.warn('Failed to parse network headers:', e);
      }

      // If we have a valid IP, derive network details
      if (isIpv4) {
        const parts = rawIp.split('.');
        const networkId = `${parts[0]}.${parts[1]}.${parts[2]}`;
        
        // Smart network info derivation based on IP class
        let subnetMask = '255.255.255.0'; // Default for class C
        if (rawIp.startsWith('10.')) {
          subnetMask = '255.0.0.0';  // Class A private
        } else if (rawIp.match(/^172\.(1[6-9]|2[0-9]|3[0-1])\./)) {
          subnetMask = '255.240.0.0';  // Class B private
        }
        
        // Derive gateway and network details
        const defaultGateway = clientInfo.gateway || `${networkId}.1`;
        
        // Use client-provided DNS or fallback to gateway + Google DNS
        const dnsServers = clientInfo.dnsServers ? 
          clientInfo.dnsServers.split(',') :
          [defaultGateway, '8.8.8.8'];
        
        networkInfo = {
          ssid: clientInfo.ssid || null,
          ipv4: rawIp,
          subnetMask,
          defaultGateway,
          dhcpServer: clientInfo.dhcpServer || null, // don't assume DHCP = gateway
          dnsServers,
          connectionType: clientInfo.type || 'unknown',
          signalStrength: clientInfo.signalStrength || null,
          networkSpeed: clientInfo.speed || null,
          leaseObtained: new Date().toISOString(),
          leaseExpires: new Date(Date.now() + 24*60*60*1000).toISOString(), // +24h
          timestamp: new Date().toISOString(),
          note: 'Enhanced client network info from browser APIs'
        };
      } else {
        // No valid IP detected
        networkInfo = {
          ssid: null,
          ipv4: null,
          subnetMask: null,
          defaultGateway: null,
          dhcpServer: null,
          dnsServers: null,
          connectionType: clientInfo.type || 'unknown',
          signalStrength: null,
          networkSpeed: null,
          leaseObtained: null,
          leaseExpires: null,
          timestamp: new Date().toISOString(),
          note: 'No valid client IPv4 detected'
        };
      }
    } else {
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
        networkInfo = {
          ssid: parseSSID(netshOutput) || null,
          ipv4: ipInfo.ipv4 || null,
          publicIp: req.query.publicIp || null, // Get public IP from query
          subnetMask: ipInfo.subnetMask || null,
          defaultGateway: ipInfo.defaultGateway || null,
          dhcpServer: ipInfo.dhcpServer || null,
          dnsServers: ipInfo.dnsServers || null,
          connectionSpecificDnsSuffix: ipInfo.connectionSpecificDnsSuffix || null,
          dhcpv6Iaid: ipInfo.dhcpv6Iaid || null,
          dhcpv6ClientDuid: ipInfo.dhcpv6ClientDuid || null,
          leaseObtained: ipInfo.leaseObtained || null,
          leaseExpires: ipInfo.leaseExpires || null,
          timestamp: new Date().toISOString(),
          note: 'Data from local Windows commands.'
        };
    }

    // Save to Supabase
    const { data, error } = await supabase
      .from('network_info')
      .insert([networkInfo]);

    if (error) {
      console.error('Supabase error:', error);
      return res.status(500).json({
        error: 'Failed to save data to Supabase',
        message: error.message
      });
    }

    res.status(200).json(networkInfo);
  } catch (error) {
    res.status(500).json({
      error: "Failed to get network information",
      message: error.message
    });
  }
};

module.exports = allowCors(handler);
