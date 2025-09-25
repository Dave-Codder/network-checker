const express = require("express");
const { exec } = require("child_process");
const app = express();
const PORT = 5000;

app.get("/network", (req, res) => {
  exec("ipconfig /all", (err, stdout) => {
    if (err) return res.status(500).json({ error: err.message });

    const ssidMatch = stdout.match(/SSID[ .:]+(.+)/);
    const ipv4Match = stdout.match(/IPv4 Address[ .:]+(.+)/);
    const maskMatch = stdout.match(/Subnet Mask[ .:]+(.+)/);
    const gatewayMatch = stdout.match(/Default Gateway[ .:]+(.+)/);
    const dhcpMatch = stdout.match(/DHCP Server[ .:]+(.+)/);

    res.json({
      ssid: ssidMatch ? ssidMatch[1].trim() : null,
      ipv4: ipv4Match ? ipv4Match[1].trim() : null,
      subnetMask: maskMatch ? maskMatch[1].trim() : null,
      defaultGateway: gatewayMatch ? gatewayMatch[1].trim() : null,
      dhcpServer: dhcpMatch ? dhcpMatch[1].trim() : null
    });
  });
});

app.listen(PORT, () => console.log(`Agent running at http://localhost:${PORT}`));
