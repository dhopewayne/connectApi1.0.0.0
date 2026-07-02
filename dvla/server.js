const express = require('express');
const cors = require('cors');
const http = require('http');
const socketIo = require('socket.io');
const os = require('os');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: { origin: '*', methods: ['GET', 'POST'] },
    pingTimeout: 60000,
    pingInterval: 25000
});

const PORT = process.env.PORT || 3000;

// ============= MIDDLEWARE =============
app.use(express.json({ limit: '50mb' }));
app.use(cors());

// ============= STORAGE =============
let latestData = {
    records: [],
    lastUpdate: null,
    source: null,
    table: null,
    count: 0
};

let connectedBranches = new Map();
let dataHistory = [];
const MAX_HISTORY = 50;

// ============= WHITELIST CONFIGURATION =============
let whitelistedNetworks = process.env.WHITELISTED_NETWORKS
    ? process.env.WHITELISTED_NETWORKS.split(',').map(network => network.trim()).filter(Boolean)
    : [];

let whitelistedStaticIps = process.env.WHITELISTED_STATIC_IPS
    ? process.env.WHITELISTED_STATIC_IPS.split(',').map(ip => ip.trim()).filter(Boolean)
    : [];

// ============= LOGGING =============
app.use((req, res, next) => {
    console.log(`\n🔵 [${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
    next();
});

// ============= HELPER: Get Client IP from Headers =============
function getClientIp(req) {
    const candidates = [
        req.headers['cf-connecting-ip'],
        req.headers['x-forwarded-for'],
        req.headers['x-real-ip'],
        req.headers['true-client-ip'],
        req.headers['x-client-ip'],
        req.socket && req.socket.remoteAddress,
        req.connection && req.connection.remoteAddress
    ];

    for (let i = 0; i < candidates.length; i++) {
        const raw = candidates[i];
        if (!raw) continue;
        const ip = raw.split(',')[0].trim();
        if (!ip) continue;
        if (ip.startsWith('::ffff:')) return ip.slice(7);
        if (ip === '::1') return '127.0.0.1';
        return ip;
    }

    return 'Unknown';
}

// ============= HELPER: Check if IP is in private range =============
function isIpInPrivateRange(ip) {
    if (!ip || ip === 'Unknown') return false;
    
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4) return false;
    if (parts.some(isNaN)) return false;
    
    // 10.0.0.0/8
    if (parts[0] === 10) return true;
    
    // 172.16.0.0/12
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    
    // 192.168.0.0/16
    if (parts[0] === 192 && parts[1] === 168) return true;
    
    // 127.0.0.0/8
    if (parts[0] === 127) return true;
    
    return false;
}

// ============= HELPER: Check if IP is in whitelisted network =============
function isIpInWhitelistedNetwork(ip) {
    if (!ip || whitelistedNetworks.length === 0) return false;
    
    const ipParts = ip.split('.').map(Number);
    if (ipParts.length !== 4 || ipParts.some(isNaN)) return false;
    
    for (const whitelisted of whitelistedNetworks) {
        const [network, maskBits] = whitelisted.split('/');
        if (!network || !maskBits) continue;
        
        const networkParts = network.split('.').map(Number);
        if (networkParts.length !== 4 || networkParts.some(isNaN)) continue;
        
        const mask = parseInt(maskBits);
        const cidrMask = ~0 << (32 - mask);
        
        const ipNum = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
        const networkNum = (networkParts[0] << 24) | (networkParts[1] << 16) | (networkParts[2] << 8) | networkParts[3];
        
        if ((ipNum & cidrMask) === (networkNum & cidrMask)) {
            return true;
        }
    }
    
    return false;
}

// ============= HELPER: Get Network Info with Router ID =============
// function getNetworkInfo(ip) {
//     const info = {
//         ip: ip,
//         router_id: null,
//         network_range: null,
//         is_private: false,
//         is_whitelisted: false,
//         whitelist_method: null,
//         network_type: 'unknown'
//     };

//     // Check if private
//     info.is_private = isIpInPrivateRange(ip);

//     // Get router ID (Gateway) - typically .1 in the subnet
//     if (ip && ip !== 'Unknown') {
//         const parts = ip.split('.');
//         if (parts.length === 4) {
//             // Router is usually .1 or .254 in the subnet
//             // Try .1 first (most common)
//             info.router_id = `${parts[0]}.${parts[1]}.${parts[2]}.1`;
            
//             // Get network range
//             info.network_range = `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
//         }
//     }

//     // Check if IP is whitelisted (static IP)
//     if (whitelistedStaticIps.includes(ip)) {
//         info.is_whitelisted = true;
//         info.whitelist_method = 'Static IP';
//         return info;
//     }

//     // Check if IP is in whitelisted network
//     if (isIpInWhitelistedNetwork(ip)) {
//         info.is_whitelisted = true;
//         info.whitelist_method = 'Network Range';
//         return info;
//     }

//     // Determine network type
//     if (info.is_private) {
//         if (ip.startsWith('192.168.')) {
//             info.network_type = 'Private (Class C)';
//         } else if (ip.startsWith('10.')) {
//             info.network_type = 'Private (Class A)';
//         } else if (ip.startsWith('172.')) {
//             info.network_type = 'Private (Class B)';
//         } else if (ip.startsWith('127.')) {
//             info.network_type = 'Localhost';
//         }
//     } else {
//         info.network_type = 'Public';
//     }

//     return info;
// }

// ============= ENDPOINT: Check My Network Status =============
// This is the endpoint you hit from your company PC
// It shows your local PC IP, router ID, and if you're whitelisted
// app.get('/my-network-check', (req, res) => {
//     const clientIp = getClientIp(req);
//     const networkInfo = getNetworkInfo(clientIp);
    
//     console.log(`\n🖥️ NETWORK CHECK from ${clientIp}`);
//     console.log(`   Router ID: ${networkInfo.router_id}`);
//     console.log(`   Whitelisted: ${networkInfo.is_whitelisted}`);
    
//     // Get all network interfaces for this PC (server-side)
//     const serverInterfaces = getServerNetworkInterfaces();
    
//     res.json({
//         success: true,
//         your_network: {
//             // Your PC's local IP (what the server sees)
//             local_pc_ip: clientIp,
            
//             // Your router/gateway ID
//             router_id: networkInfo.router_id,
            
//             // Your network range
//             network_range: networkInfo.network_range,
            
//             // Network type
//             network_type: networkInfo.network_type,
            
//             // Is this a private network?
//             is_private: networkInfo.is_private,
            
//             // Are you whitelisted?
//             is_whitelisted: networkInfo.is_whitelisted,
            
//             // How you're whitelisted (if applicable)
//             whitelist_method: networkInfo.whitelist_method
//         },
        
//         whitelist_status: {
//             status: networkInfo.is_whitelisted ? '✅ ALLOWED' : '❌ DENIED',
//             message: networkInfo.is_whitelisted 
//                 ? `Your PC (${clientIp}) is authorized to access this server`
//                 : `Your PC (${clientIp}) is NOT authorized to access this server`
//         },
        
//         // Server's network info for reference
//         server_network: {
//             server_local_ips: serverInterfaces,
//             whitelisted_networks: whitelistedNetworks,
//             whitelisted_static_ips: whitelistedStaticIps
//         },
        
//         // Helpful actions
//         actions: {
//             if_not_whitelisted: {
//                 method_1: `Add your IP as static: WHITELISTED_STATIC_IPS=${clientIp}`,
//                 method_2: `Add your network: WHITELISTED_NETWORKS=${networkInfo.network_range || '192.168.1.0/24'}`,
//                 method_3: `POST to /whitelist/static with: { "ips": ["${clientIp}"] }`,
//                 method_4: `POST to /whitelist/network with: { "networks": ["${networkInfo.network_range || '192.168.1.0/24'}"] }`
//             }
//         },
        
//         timestamp: new Date().toISOString()
//     });
// });  






// ============= HELPER: Get Network Info with Better Detection =============
function getNetworkInfo(ip) {
    const info = {
        ip: ip,
        router_id: null,
        network_range: null,
        subnet_mask: null,
        is_private: false,
        is_whitelisted: false,
        whitelist_method: null,
        network_type: 'unknown',
        recommendation: null
    };

    // Check if private
    info.is_private = isIpInPrivateRange(ip);

    // Get network details
    if (ip && ip !== 'Unknown') {
        const parts = ip.split('.');
        if (parts.length === 4) {
            // Router is usually .1 in the subnet
            info.router_id = `${parts[0]}.${parts[1]}.${parts[2]}.1`;
            
            // Network range
            info.network_range = `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
            
            // Subnet mask (default for /24)
            info.subnet_mask = '255.255.255.0';
        }
    }

    // Check if IP is whitelisted (static IP)
    if (whitelistedStaticIps.includes(ip)) {
        info.is_whitelisted = true;
        info.whitelist_method = 'Static IP (Recommended for your setup)';
        info.recommendation = 'Your IP is whitelisted as a static IP';
        return info;
    }

    // Check if IP is in whitelisted network
    if (isIpInWhitelistedNetwork(ip)) {
        info.is_whitelisted = true;
        info.whitelist_method = 'Network Range';
        info.recommendation = 'Your network is whitelisted';
        return info;
    }

    // Determine network type and recommendation
    if (info.is_private) {
        if (ip.startsWith('192.168.')) {
            info.network_type = 'Private (Class C - Home/Office)';
            info.recommendation = 'Add your network range or static IP';
        } else if (ip.startsWith('10.')) {
            info.network_type = 'Private (Class A - Large Network)';
            info.recommendation = 'Add your network range or static IP';
        } else if (ip.startsWith('172.')) {
            info.network_type = 'Private (Class B - Medium Network)';
            info.recommendation = 'Add your network range or static IP';
        }
    } else {
        info.network_type = `Public IP (${ip}) - Likely a Company Static IP`;
        info.recommendation = 'Since this is a public static IP, add it as a STATIC IP, not a network range';
    }

    return info;
}

// ============= ENDPOINT: Check My Network Status (Enhanced) =============
app.get('/my-network-check', (req, res) => {
    const clientIp = getClientIp(req);
    const networkInfo = getNetworkInfo(clientIp);
    
    console.log(`\n🖥️ NETWORK CHECK from ${clientIp}`);
    console.log(`   Router ID: ${networkInfo.router_id}`);
    console.log(`   Whitelisted: ${networkInfo.is_whitelisted}`);
    console.log(`   Network Type: ${networkInfo.network_type}`);
    
    res.json({
        success: true,
        your_network: {
            // Your PC's IP
            local_pc_ip: clientIp,
            
            // Your router/gateway
            router_id: networkInfo.router_id,
            
            // Your network range
            network_range: networkInfo.network_range,
            
            // Subnet mask
            subnet_mask: networkInfo.subnet_mask,
            
            // Network type
            network_type: networkInfo.network_type,
            
            // Is this a private network?
            is_private: networkInfo.is_private,
            
            // Are you whitelisted?
            is_whitelisted: networkInfo.is_whitelisted,
            
            // How you're whitelisted (if applicable)
            whitelist_method: networkInfo.whitelist_method,
            
            // Recommendation
            recommendation: networkInfo.recommendation
        },
        
        whitelist_status: {
            status: networkInfo.is_whitelisted ? '✅ ALLOWED' : '❌ DENIED',
            message: networkInfo.is_whitelisted 
                ? `Your PC (${clientIp}) is authorized to access this server`
                : `Your PC (${clientIp}) is NOT authorized to access this server`
        },
        
        // ⭐ IMPORTANT: Based on your network type, this shows the BEST method
        recommended_action: networkInfo.is_private ? {
            method: 'Network Range (CIDR)',
            value: networkInfo.network_range,
            command: `curl -X POST /whitelist/network -H "Content-Type: application/json" -d '{"networks": ["${networkInfo.network_range}"]}'`,
            note: 'Use network range if other PCs in your company need access'
        } : {
            method: 'Static IP (Recommended for your setup)',
            value: clientIp,
            command: `curl -X POST /whitelist/static -H "Content-Type: application/json" -d '{"ips": ["${clientIp}"]}'`,
            note: 'Use static IP since your IP is public and fixed'
        },
        
        // All possible actions
        actions: {
            // For static IP (RECOMMENDED for you)
            add_static_ip: {
                method: `Add your IP as a static IP`,
                value: clientIp,
                command: `curl -X POST /whitelist/static -H "Content-Type: application/json" -d '{"ips": ["${clientIp}"]}'`,
                why: 'Your IP is public and static - this is the most secure method'
            },
            
            // For network range (if others need access)
            add_network_range: {
                method: `Add your network range`,
                value: networkInfo.network_range,
                command: `curl -X POST /whitelist/network -H "Content-Type: application/json" -d '{"networks": ["${networkInfo.network_range}"]}'`,
                why: 'Use this if other PCs in your company need access (IPs in the same range)'
            },
            
            // Environment variable method
            env_method: {
                static_ip: `WHITELISTED_STATIC_IPS=${clientIp}`,
                network_range: `WHILISTED_NETWORKS=${networkInfo.network_range}`
            }
        },
        
        // Server's current whitelist
        server_whitelist: {
            static_ips: whitelistedStaticIps,
            networks: whitelistedNetworks
        },
        
        timestamp: new Date().toISOString()
    });
});

// ============= HELPER: Get Server Network Interfaces =============
function getServerNetworkInterfaces() {
    try {
        const interfaces = os.networkInterfaces();
        const results = [];
        
        for (const name of Object.keys(interfaces)) {
            for (const iface of interfaces[name]) {
                if (!iface.internal && iface.family === 'IPv4') {
                    results.push({
                        interface: name,
                        address: iface.address,
                        netmask: iface.netmask
                    });
                }
            }
        }
        
        return results;
    } catch (error) {
        return [];
    }
}

// ============= WHITELIST MANAGEMENT ENDPOINTS =============

// GET - View whitelist
app.get('/whitelist', (req, res) => {
    res.json({
        success: true,
        whitelist: {
            static_ips: whitelistedStaticIps,
            networks: whitelistedNetworks
        },
        counts: {
            static_ips: whitelistedStaticIps.length,
            networks: whitelistedNetworks.length,
            total: whitelistedStaticIps.length + whitelistedNetworks.length
        }
    });
});

// POST - Add static IPs
app.post('/whitelist/static', (req, res) => {
    const { ips } = req.body;
    const clientIp = getClientIp(req);

    if (!ips) {
        return res.status(400).json({
            success: false,
            error: 'Missing field: ips',
            example: { ips: ['192.168.1.100'] }
        });
    }

    const incoming = (Array.isArray(ips) ? ips : [ips])
        .map(ip => ip.trim())
        .filter(Boolean);

    const added = [];
    const alreadyExist = [];
    for (const ip of incoming) {
        if (!whitelistedStaticIps.includes(ip)) {
            whitelistedStaticIps.push(ip);
            added.push(ip);
        } else {
            alreadyExist.push(ip);
        }
    }

    res.json({
        success: true,
        added: added,
        already_existed: alreadyExist,
        static_ips: whitelistedStaticIps,
        message: `Added ${added.length} static IP(s)`
    });
});

// POST - Add network ranges
app.post('/whitelist/network', (req, res) => {
    const { networks } = req.body;

    if (!networks) {
        return res.status(400).json({
            success: false,
            error: 'Missing field: networks',
            example: { networks: ['192.168.1.0/24'] }
        });
    }

    const incoming = (Array.isArray(networks) ? networks : [networks])
        .map(network => network.trim())
        .filter(Boolean);

    const added = [];
    const alreadyExist = [];
    for (const network of incoming) {
        if (!whitelistedNetworks.includes(network)) {
            whitelistedNetworks.push(network);
            added.push(network);
        } else {
            alreadyExist.push(network);
        }
    }

    res.json({
        success: true,
        added: added,
        already_existed: alreadyExist,
        networks: whitelistedNetworks,
        message: `Added ${added.length} network(s)`
    });
});

// DELETE - Remove from whitelist
app.delete('/whitelist', (req, res) => {
    const { type, value } = req.body;

    if (!type || !value) {
        return res.status(400).json({
            success: false,
            error: 'Missing fields: type and value',
            example: { type: 'static', value: '192.168.1.100' }
        });
    }

    let removed = false;

    if (type === 'static') {
        const index = whitelistedStaticIps.indexOf(value);
        if (index !== -1) {
            whitelistedStaticIps.splice(index, 1);
            removed = true;
        }
    } else if (type === 'network') {
        const index = whitelistedNetworks.indexOf(value);
        if (index !== -1) {
            whitelistedNetworks.splice(index, 1);
            removed = true;
        }
    }

    if (!removed) {
        return res.status(404).json({
            success: false,
            error: `${type} ${value} not found in whitelist`
        });
    }

    res.json({
        success: true,
        message: `Removed ${type} ${value}`,
        remaining: {
            static_ips: whitelistedStaticIps,
            networks: whitelistedNetworks
        }
    });
});

// ============= PROTECTED ENDPOINTS =============
// Authentication middleware
const authenticateBranch = (req, res, next) => {
    const clientIp = getClientIp(req);
    const networkInfo = getNetworkInfo(clientIp);

    console.log(`\n🔐 AUTH CHECK:`);
    console.log(`   IP: ${clientIp}`);
    console.log(`   Router: ${networkInfo.router_id}`);
    console.log(`   Whitelisted: ${networkInfo.is_whitelisted}`);

    if (!networkInfo.is_whitelisted) {
        return res.status(403).json({
            success: false,
            error: 'Access denied',
            reason: 'Your network is not whitelisted',
            your_ip: clientIp,
            router_id: networkInfo.router_id,
            network_range: networkInfo.network_range,
            how_to_fix: {
                add_static_ip: `POST /whitelist/static with { "ips": ["${clientIp}"] }`,
                add_network: `POST /whitelist/network with { "networks": ["${networkInfo.network_range}"] }`
            }
        });
    }

    next();
};

// Apply authentication to protected routes
app.use('/testresults', authenticateBranch);
app.use('/data', authenticateBranch);

// ============= TEST ENDPOINTS =============
app.get('/testresults', (req, res) => {
    res.json({
        success: true,
        message: 'Protected endpoint - you are authenticated!',
        data: latestData
    });
});

app.get('/data', (req, res) => {
    res.json({
        success: true,
        message: 'Protected data endpoint',
        records: latestData.records || []
    });
});

// ============= ROOT ENDPOINT =============
app.get('/', (req, res) => {
    res.json({
        name: 'Company Network Authentication Server',
        status: 'online',
        endpoints: {
            'GET /my-network-check': 'Check if your PC/network is whitelisted (HIT THIS FROM YOUR PC)',
            'GET /whitelist': 'View whitelist',
            'POST /whitelist/static': 'Add static IPs',
            'POST /whitelist/network': 'Add network ranges',
            'DELETE /whitelist': 'Remove from whitelist'
        },
        example_usage: {
            check_network: 'GET /my-network-check',
            add_your_ip: 'POST /whitelist/static with { "ips": ["YOUR_IP_HERE"] }',
            add_your_network: 'POST /whitelist/network with { "networks": ["YOUR_NETWORK_HERE"] }'
        },
        timestamp: new Date().toISOString()
    });
});

// ============= START SERVER =============
server.listen(PORT, () => {
    console.log(`
    ═══════════════════════════════════════════════════════
    🏢 COMPANY NETWORK AUTHENTICATION SERVER
    ═══════════════════════════════════════════════════════
    📍 URL:        http://localhost:${PORT}
    
    📡 HIT THIS ENDPOINT FROM YOUR PC:
       GET /my-network-check
       
       This will show:
       ✅ Your local PC IP
       ✅ Your Router/Gateway ID
       ✅ Your Network Range
       ✅ If you're whitelisted or not
    
    💡 Example:
       curl http://localhost:${PORT}/my-network-check
    
    ═══════════════════════════════════════════════════════
    `);
});

console.log(`
╔═══════════════════════════════════════════════════════════╗
║                                                          ║
║  🖥️  FROM YOUR COMPANY PC, RUN:                         ║
║                                                          ║
║  curl http://YOUR_SERVER_IP:${PORT}/my-network-check      ║
║                                                          ║
║  This will show:                                        ║
║                                                          ║
║  {                                                      ║
║    "your_network": {                                   ║
║      "local_pc_ip": "192.168.0.12",     ← Your PC IP   ║
║      "router_id": "192.168.0.1",        ← Router/Gateway║
║      "network_range": "192.168.0.0/24", ← Your Network  ║
║      "is_whitelisted": true/false       ← Status       ║
║    }                                                   ║
║  }                                                      ║
║                                                          ║
║  If NOT whitelisted, add your network:                  ║
║  POST /whitelist/network                               ║
║  { "networks": ["192.168.0.0/24"] }                    ║
║                                                          ║
╚═══════════════════════════════════════════════════════════╝
`);