const { createClient } = require('@supabase/supabase-js');
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

// Parsing functions (remains the same)
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
  const mIaid = output.match(reDhcpV6Iaid);
  if (mIaid) result.dhcpv6Iaid = mIaid[1].trim();
  const mDuid = output.match(reDhcpV6Duid);
  if (mDuid) result.dhcpv6ClientDuid = mDuid[1].trim();
  const mDns = output.match(reDnsServers);
  if (mDns) {
    const first = mDns[1].trim();
    const dnsList = [first];
    const after = output.slice(output.indexOf(mDns[0]) + mDns[0].length);
    const lines = after.split(/\r?\n/);
    for (const ln of lines) {
      const trimmed = ln.trim();
      if (!trimmed) break;
      if (/^[0-9]/.test(trimmed)) dnsList.push(trimmed.split(/\s+/)[0]);
      else break;
    }
    result.dnsServers = dnsList;
  }
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

  // Check for all required environment variables
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_ANON_KEY || !process.env.IPINFO_TOKEN) {
    return res.status(500).json({
      error: 'Environment variables not set.',
      message: 'Please ensure SUPABASE_URL, SUPABASE_ANON_KEY, and IPINFO_TOKEN are set in your Vercel project settings.'
    });
  }

  const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

  try {
    // Get the user's IP from headers. Vercel populates 'x-forwarded-for'.
    const userIp = req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0] : '127.0.0.1';

    // Securely fetch the USER's public IP info from the backend
    const ipinfoResponse = await fetch(`https://ipinfo.io/${userIp}/json?token=${process.env.IPINFO_TOKEN}`);
    if (!ipinfoResponse.ok) {
      throw new Error(`ipinfo.io API error: ${ipinfoResponse.statusText}`);
    }
    const publicIpData = await ipinfoResponse.json();

    let networkInfo;

    if (process.platform !== 'win32') {
      const { privateIp } = req.query;
      const ipv4Regex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
      const isPrivateIpv4 = ipv4Regex.test(privateIp);
      let subnetMask = 'Tidak diketahui';
      let defaultGateway = 'Tidak diketahui';
      let networkId = 'Tidak diketahui';

      if (isPrivateIpv4) {
        if (privateIp.startsWith('10.')) subnetMask = '255.0.0.0';
        else if (privateIp.startsWith('192.168.')) subnetMask = '255.255.255.0';
        else if (privateIp.match(/^172\.(1[6-9]|2[0-9]|3[0-1])\./)) subnetMask = '255.240.0.0';
        const parts = privateIp.split('.');
        networkId = `${parts[0]}.${parts[1]}.${parts[2]}.0`;
        defaultGateway = `${parts[0]}.${parts[1]}.${parts[2]}.1`;
      }
      
      networkInfo = {
        ssid: req.query.ssid || null,
        ipv4: privateIp || null,
        publicIp: publicIpData.ip || null,
        city: publicIpData.city,
        region: publicIpData.region,
        country: publicIpData.country,
        org: publicIpData.org,
        loc: publicIpData.loc,
        postal: publicIpData.postal,
        timezone: publicIpData.timezone,
        subnetMask: subnetMask,
        defaultGateway: defaultGateway,
        networkId: networkId,
        dnsServers: [defaultGateway, '8.8.8.8'],
        timestamp: new Date().toISOString(),
        note: 'Data from client (WebRTC) via query parameters.'
      };
    } else {
        let netshOutput = '';
        let ipOutput = '';
        try {
          const { stdout: netshStdout } = await execAsync('netsh wlan show interfaces');
          netshOutput = netshStdout;
        } catch (err) {
          console.warn('WLAN information not available:', err.message);
        }

        let ipInfo = {};
        try {
          const { stdout: ipStdout } = await execAsync('ipconfig /all');
          ipOutput = ipStdout;
          ipInfo = parseIpconfig(ipOutput);
        } catch (err) {
          return res.status(500).json({ error: 'Command execution failed', message: 'Failed to get network information', details: err.message });
        }

        if (!ipInfo.ipv4) {
          return res.status(404).json({ error: 'No data', message: 'No network adapter information found' });
        }

        networkInfo = {
          ssid: parseSSID(netshOutput) || null,
          ipv4: ipInfo.ipv4 || null,
          publicIp: publicIpData.ip || null,
          city: publicIpData.city,
          region: publicIpData.region,
          country: publicIpData.country,
          org: publicIpData.org,
          loc: publicIpData.loc,
          postal: publicIpData.postal,
          timezone: publicIpData.timezone,
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

    // Map to snake_case for Supabase insertion
    const snakeCaseNetworkInfo = {
      ssid: networkInfo.ssid,
      ipv4: networkInfo.ipv4,
      public_ip: networkInfo.publicIp,
      city: networkInfo.city,
      region: networkInfo.region,
      country: networkInfo.country,
      org: networkInfo.org,
      loc: networkInfo.loc,
      postal: networkInfo.postal,
      timezone: networkInfo.timezone,
      subnet_mask: networkInfo.subnetMask,
      default_gateway: networkInfo.defaultGateway,
      network_id: networkInfo.networkId,
      dhcp_server: networkInfo.dhcpServer,
      dns_servers: networkInfo.dnsServers,
      connection_type: networkInfo.connectionType,
      signal_strength: networkInfo.signalStrength,
      network_speed: networkInfo.networkSpeed,
      lease_obtained: networkInfo.leaseObtained,
      lease_expires: networkInfo.leaseExpires,
      timestamp: networkInfo.timestamp,
      note: networkInfo.note,
      connection_specific_dns_suffix: networkInfo.connectionSpecificDnsSuffix,
      dhcpv6_iaid: networkInfo.dhcpv6Iaid,
      dhcpv6_client_duid: networkInfo.dhcpv6ClientDuid
    };

    const { data, error } = await supabase.from('network_info').insert([snakeCaseNetworkInfo]);

    if (error) {
      console.error('Supabase error:', error);
      return res.status(500).json({ error: 'Failed to save data to Supabase', message: error.message });
    }

    res.status(200).json(networkInfo);
  } catch (error) {
    res.status(500).json({ error: "Failed to get network information", message: error.message });
  }
};

module.exports = allowCors(handler);
