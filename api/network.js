// Vercel Serverless Function
module.exports = async (req, res) => {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET');
  res.setHeader('Content-Type', 'application/json');

  try {
    // Get client's IP address from Vercel's headers
    const clientIp = req.headers['x-forwarded-for'] || 
                    req.headers['x-real-ip'] || 
                    req.socket.remoteAddress;

    // For deployed version, we return basic network info
    const networkInfo = {
      clientIp: clientIp,
      timestamp: new Date().toISOString(),
      message: "Full network information is only available when running locally",
      deployedOn: "Vercel",
      isDeployed: true
    };

    res.status(200).json(networkInfo);
  } catch (error) {
    res.status(500).json({
      error: "Failed to get network information",
      message: error.message
    });
  }
};