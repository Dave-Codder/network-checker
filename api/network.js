// Vercel Serverless Function for Network Information
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

const handler = async (req, res) => {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET');
  res.setHeader('Content-Type', 'application/json');

  try {
    // Get client's IP and other network information
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || 
                    req.headers['x-real-ip'] || 
                    req.connection.remoteAddress;

    // Get user agent information
    const userAgent = req.headers['user-agent'];

    // Get connection information
    const connection = req.headers['connection'];
    const protocol = req.headers['x-forwarded-proto'] || 'http';

    // Get DNS information
    const host = req.headers['host'];

    // Build network information object
    const networkInfo = {
      ipAddress: clientIp,
      connectionInfo: {
        protocol: protocol,
        type: connection,
        host: host
      },
      clientInfo: {
        userAgent: userAgent,
        platform: process.platform,
        timestamp: new Date().toISOString()
      },
      headers: {
        accept: req.headers['accept'],
        language: req.headers['accept-language'],
        encoding: req.headers['accept-encoding']
      }
    };

    // Add geolocation information if available through Vercel headers
    if (req.headers['x-vercel-ip-country']) {
      networkInfo.geo = {
        country: req.headers['x-vercel-ip-country'],
        region: req.headers['x-vercel-ip-country-region'],
        city: req.headers['x-vercel-ip-city']
      };
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