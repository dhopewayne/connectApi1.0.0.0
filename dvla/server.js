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

// In-memory allowed IPs list — seeded from .env, updated via POST /allowed-ips
let allowedIps = process.env.ALLOWED_IPS
    ? process.env.ALLOWED_IPS.split(',').map(ip => ip.trim()).filter(Boolean)
    : [];

// Separate list for server IPs that are whitelisted for internal use
let whitelistedServerIps = process.env.WHITELISTED_SERVER_IPS
    ? process.env.WHITELISTED_SERVER_IPS.split(',').map(ip => ip.trim()).filter(Boolean)
    : [];

// ============= LOGGING =============
app.use((req, res, next) => {
    console.log(`\n🔵 [${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
    next();
});

// ============= HELPER: Get Real Client Public IP =============
// Checks headers in priority order. Works on Render, Railway,
// Heroku, Fly.io, Cloudflare, Nginx, bare Node — every platform.
function getClientIp(req) {
    const candidates = [
        req.headers['cf-connecting-ip'],    // Cloudflare
        req.headers['x-forwarded-for'],     // Most proxies / load balancers
        req.headers['x-real-ip'],           // Nginx
        req.headers['true-client-ip'],      // Akamai / Cloudflare Enterprise
        req.headers['x-client-ip'],         // Some CDNs
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

// ============= HELPER: Get Local Network IPs =============
function getLocalNetworkIps() {
    try {
        const interfaces = os.networkInterfaces();
        const localIps = [];
        const allIps = [];
        
        for (const name of Object.keys(interfaces)) {
            for (const iface of interfaces[name]) {
                // Skip internal (localhost) and non-IPv4
                if (!iface.internal && iface.family === 'IPv4') {
                    localIps.push({
                        interface: name,
                        address: iface.address,
                        netmask: iface.netmask,
                        mac: iface.mac
                    });
                }
                
                // Collect all IPv4 addresses for debugging
                if (iface.family === 'IPv4') {
                    allIps.push({
                        interface: name,
                        address: iface.address,
                        internal: iface.internal,
                        netmask: iface.netmask
                    });
                }
            }
        }
        
        return {
            local_ips: localIps,
            all_ips: allIps,
            primary_ip: localIps.length > 0 ? localIps[0].address : '127.0.0.1'
        };
    } catch (error) {
        console.error('Error getting local network IPs:', error);
        return {
            local_ips: [],
            all_ips: [],
            primary_ip: 'Unable to determine'
        };
    }
}

// ============= AUTHENTICATION =============
// Reads ALLOWED_IPS and ALLOWED_MACS from .env
//
// .env example:
//   ALLOWED_IPS=41.58.120.5,41.58.120.6
//   ALLOWED_MACS=AA:BB:CC:DD:EE:FF,11:22:33:44:55:66
//   WHITELISTED_SERVER_IPS=192.168.1.100,192.168.1.101
//
// Rules:
//   - If ALLOWED_IPS is set   → request's public IP must be in the list
//   - If ALLOWED_MACS is set  → x-mac-address header must be in the list
//   - If BOTH are set         → BOTH must pass (strictest)
//   - If NEITHER is set       → open access (dev mode)

const authenticateBranch = (req, res, next) => {
    const clientIp  = getClientIp(req);
    const clientMac = (req.headers['x-mac-address'] || '').toUpperCase();

    const allowedMacs = process.env.ALLOWED_MACS
        ? process.env.ALLOWED_MACS.split(',').map(m => m.trim().toUpperCase())
        : [];

    console.log(`\n🔐 AUTH CHECK:`);
    console.log(`   📍 Client Public IP : ${clientIp}`);
    console.log(`   🖥️  Client MAC       : ${clientMac || 'Not provided'}`);
    console.log(`   ✅ Allowed IPs       : ${allowedIps.length  ? allowedIps.join(', ')  : 'Any (not set)'}`);
    console.log(`   ✅ Allowed MACs      : ${allowedMacs.length ? allowedMacs.join(', ') : 'Any (not set)'}`);

    // --- IP check ---
    if (allowedIps.length === 0) {
        console.log(`   ❌ No IPs whitelisted yet — access denied`);
        return res.status(403).json({
            success: false,
            error:   'Access denied',
            reason:  'No IPs have been whitelisted yet. POST to /allowed-ips first.'
        });
    }

    if (!allowedIps.includes(clientIp)) {
        console.log(`   ❌ IP NOT ALLOWED: ${clientIp}`);
        return res.status(403).json({
            success: false,
            error:   'Access denied',
            reason:  `Your public IP (${clientIp}) is not on the allowed list.`,
            hint:    'Ask the admin to add your IP via POST /allowed-ips'
        });
    }

    // --- MAC check ---
    if (allowedMacs.length > 0) {
        if (!clientMac) {
            console.log(`   ❌ MAC required but not provided`);
            return res.status(401).json({
                success: false,
                error:   'MAC address required',
                reason:  'Send your MAC in the x-mac-address request header.'
            });
        }
        if (!allowedMacs.includes(clientMac)) {
            console.log(`   ❌ MAC NOT ALLOWED: ${clientMac}`);
            return res.status(403).json({
                success: false,
                error:   'Access denied',
                reason:  `Your MAC address (${clientMac}) is not on the allowed list.`
            });
        }
    }

    console.log(`   ✅ ACCESS GRANTED`);
    next();
};

// Apply authentication to protected routes
app.use('/testresults', authenticateBranch);
app.use('/data',        authenticateBranch);

// ============= ENDPOINT: Server Local Network IP + Access Check =============
// Hit this to get the server's local network IP and check if it's whitelisted
app.get('/server-ip', (req, res) => {
    const networkInfo = getLocalNetworkIps();
    const primaryIp = networkInfo.primary_ip;
    const isWhitelisted = whitelistedServerIps.includes(primaryIp);
    
    console.log(`\n🖥️ SERVER LOCAL IP REQUEST — Primary IP: ${primaryIp} | Whitelisted: ${isWhitelisted}`);
    
    // Check all local IPs against whitelist
    const ipStatus = networkInfo.local_ips.map(ip => ({
        interface: ip.interface,
        address: ip.address,
        netmask: ip.netmask,
        mac: ip.mac,
        is_whitelisted: whitelistedServerIps.includes(ip.address)
    }));
    
    if (whitelistedServerIps.length === 0) {
        return res.status(403).json({
            success: false,
            server_local_ips: networkInfo.local_ips.map(ip => ip.address),
            primary_ip: primaryIp,
            is_whitelisted: false,
            message: '❌ No server IPs have been whitelisted yet. POST to /white/s/p first.',
            network_info: networkInfo,
            suggestion: `Run: curl -X POST /white/s/p -H "Content-Type: application/json" -d '{"ips": ["${primaryIp}"]}'`
        });
    }
    
    if (isWhitelisted) {
        return res.json({
            success: true,
            server_local_ips: networkInfo.local_ips.map(ip => ip.address),
            primary_ip: primaryIp,
            is_whitelisted: true,
            message: `✅ Server local IP (${primaryIp}) is whitelisted in WHITELISTED_SERVER_IPS`,
            network_info: {
                all_interfaces: networkInfo.all_ips,
                local_interfaces: networkInfo.local_ips
            },
            server_whitelist: whitelistedServerIps,
            whitelist_count: whitelistedServerIps.length
        });
    } else {
        return res.status(403).json({
            success: false,
            server_local_ips: networkInfo.local_ips.map(ip => ip.address),
            primary_ip: primaryIp,
            is_whitelisted: false,
            message: `❌ Server local IP (${primaryIp}) is NOT whitelisted. Add it via POST /white/s/p`,
            network_info: {
                all_interfaces: networkInfo.all_ips,
                local_interfaces: networkInfo.local_ips
            },
            current_server_whitelist: whitelistedServerIps,
            suggestion: `Run: curl -X POST /white/s/p -H "Content-Type: application/json" -d '{"ips": ["${primaryIp}"]}'`
        });
    }
});

// ============= ENDPOINT: Whitelist Server Local IPs =============
// POST /white/s/p - Add server local IPs to the whitelist
// Body: { "ips": ["192.168.1.100", "192.168.1.101"] }
// or:   { "ips": "192.168.1.100" } (single string also accepted)
// GET  /white/s/p - View all whitelisted server IPs
// DELETE /white/s/p - Remove a server IP from the whitelist

// GET - View whitelisted server IPs
app.get('/white/s/p', (req, res) => {
    const networkInfo = getLocalNetworkIps();
    const primaryIp = networkInfo.primary_ip;
    
    // Check which local IPs are whitelisted
    const ipStatus = networkInfo.local_ips.map(ip => ({
        interface: ip.interface,
        address: ip.address,
        is_whitelisted: whitelistedServerIps.includes(ip.address)
    }));
    
    res.json({
        success: true,
        count: whitelistedServerIps.length,
        whitelisted_server_ips: whitelistedServerIps,
        current_server: {
            primary_ip: primaryIp,
            all_local_ips: networkInfo.local_ips.map(ip => ip.address),
            is_primary_whitelisted: whitelistedServerIps.includes(primaryIp),
            ip_status: ipStatus
        },
        note: whitelistedServerIps.length === 0
            ? 'No server IPs have been whitelisted yet'
            : 'These server local IPs are allowed for internal operations',
        usage: {
            add: 'POST /white/s/p with { "ips": ["192.168.1.100", "192.168.1.101"] }',
            remove: 'DELETE /white/s/p with { "ip": "192.168.1.100" }',
            view: 'GET /white/s/p'
        }
    });
});

// POST - Add server local IPs to whitelist
app.post('/white/s/p', (req, res) => {
    const { ips } = req.body;
    const clientIp = getClientIp(req);
    const networkInfo = getLocalNetworkIps();

    console.log(`\n📋 WHITELIST SERVER IPs REQUEST from ${clientIp}`);
    console.log(`   Request body:`, req.body);

    if (!ips) {
        return res.status(400).json({
            success: false,
            error: 'Missing field: ips',
            example: { ips: ['192.168.1.100', '192.168.1.101'] },
            note: 'You can also provide a single IP as a string: { "ips": "192.168.1.100" }'
        });
    }

    // Accept either a single string or an array
    const incoming = (Array.isArray(ips) ? ips : [ips])
        .map(ip => ip.trim())
        .filter(Boolean);

    if (incoming.length === 0) {
        return res.status(400).json({
            success: false,
            error: 'No valid IPs provided'
        });
    }

    // Validate IP format (basic validation)
    const invalidIps = [];
    const validIps = [];
    for (const ip of incoming) {
        // Simple IPv4 validation
        const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (ipv4Regex.test(ip) && ip.split('.').every(num => parseInt(num) >= 0 && parseInt(num) <= 255)) {
            validIps.push(ip);
        } else {
            invalidIps.push(ip);
        }
    }

    if (validIps.length === 0) {
        return res.status(400).json({
            success: false,
            error: 'No valid IPv4 addresses provided',
            invalid_ips: invalidIps,
            hint: 'Please provide valid IPv4 addresses (e.g., 192.168.1.100)'
        });
    }

    // Add only new ones (no duplicates)
    const added = [];
    const alreadyExist = [];
    for (const ip of validIps) {
        if (!whitelistedServerIps.includes(ip)) {
            whitelistedServerIps.push(ip);
            added.push(ip);
        } else {
            alreadyExist.push(ip);
        }
    }

    console.log(`\n📋 WHITELISTED SERVER IPs UPDATED — added: ${added.join(', ') || 'none'}`);
    console.log(`   Already existed: ${alreadyExist.join(', ') || 'none'}`);
    console.log(`   Invalid: ${invalidIps.join(', ') || 'none'}`);
    console.log(`   Full server whitelist: ${whitelistedServerIps.join(', ')}`);

    // Also check if the current server IP is now whitelisted
    const primaryIp = networkInfo.primary_ip;
    const isCurrentWhitelisted = whitelistedServerIps.includes(primaryIp);

    res.json({
        success: true,
        message: `Successfully added ${added.length} server IP(s) to the whitelist`,
        added: added,
        already_existed: alreadyExist,
        invalid: invalidIps,
        total_server_ips: whitelistedServerIps.length,
        whitelisted_server_ips: whitelistedServerIps,
        current_server: {
            primary_ip: primaryIp,
            all_local_ips: networkInfo.local_ips.map(ip => ip.address),
            is_whitelisted: isCurrentWhitelisted
        },
        timestamp: new Date().toISOString()
    });
});

// DELETE - Remove a server IP from whitelist
app.delete('/white/s/p', (req, res) => {
    const { ip } = req.body;
    const clientIp = getClientIp(req);

    console.log(`\n🗑️ REMOVE SERVER IP from whitelist — Request from ${clientIp}`);
    console.log(`   IP to remove: ${ip}`);

    if (!ip) {
        return res.status(400).json({
            success: false,
            error: 'Missing field: ip',
            example: { ip: '192.168.1.100' }
        });
    }

    const trimmedIp = ip.trim();
    const index = whitelistedServerIps.indexOf(trimmedIp);
    
    if (index === -1) {
        return res.status(404).json({
            success: false,
            error: `IP ${trimmedIp} not found in server whitelist`,
            current_server_ips: whitelistedServerIps
        });
    }

    whitelistedServerIps.splice(index, 1);
    
    console.log(`   ✅ Removed ${trimmedIp} from server whitelist`);
    console.log(`   Updated list: ${whitelistedServerIps.join(', ') || '(empty)'}`);

    const networkInfo = getLocalNetworkIps();

    res.json({
        success: true,
        message: `Successfully removed ${trimmedIp} from server whitelist`,
        removed: trimmedIp,
        remaining_server_ips: whitelistedServerIps,
        count: whitelistedServerIps.length,
        current_server: {
            primary_ip: networkInfo.primary_ip,
            all_local_ips: networkInfo.local_ips.map(ip => ip.address)
        },
        timestamp: new Date().toISOString()
    });
});

// ============= ENDPOINT: Get Server Network Info =============
// Useful for debugging - shows all network interfaces
app.get('/server-network', (req, res) => {
    const networkInfo = getLocalNetworkIps();
    res.json({
        success: true,
        network_info: networkInfo,
        whitelisted_server_ips: whitelistedServerIps,
        timestamp: new Date().toISOString()
    });
});

// ============= ENDPOINT: My IP + Access Check =============
// Hit this from any browser to see your public IP and whether you are allowed.
app.get('/my-ip', (req, res) => {
    const ip      = getClientIp(req);
    const allowed = allowedIps.includes(ip);

    console.log(`\n🌐 IP REQUEST — resolved: ${ip} | allowed: ${allowed}`);

    if (allowedIps.length === 0) {
        return res.status(403).json({
            success:        false,
            your_public_ip: ip,
            access:         'DENIED',
            message:        `❌ No IPs have been whitelisted yet. POST to /allowed-ips first.`
        });
    }

    if (allowed) {
        return res.json({
            success:        true,
            your_public_ip: ip,
            access:         'ALLOWED',
            message:        `✅ Your IP (${ip}) is authorised to access this server.`
        });
    } else {
        return res.status(403).json({
            success:        false,
            your_public_ip: ip,
            access:         'DENIED',
            message:        `❌ Your IP (${ip}) is not on the allowed list. Contact the admin.`
        });
    }
});

// ============= ENDPOINT: Allowed IPs =============
// GET  /allowed-ips         — view the current whitelist
// POST /allowed-ips         — add one or more IPs to the whitelist
//   body: { "ips": ["41.58.120.5", "102.89.47.3"] }
//   or:   { "ips": "41.58.120.5" }   (single string also accepted)

app.get('/allowed-ips', (req, res) => {
    res.json({
        success:     true,
        count:       allowedIps.length,
        allowed_ips: allowedIps,
        note:        allowedIps.length === 0
            ? 'List is empty — all IPs are currently allowed (open access)'
            : 'Only these public IPs can access protected endpoints'
    });
});

app.post('/allowed-ips', (req, res) => {
    const { ips } = req.body;

    if (!ips) {
        return res.status(400).json({
            success: false,
            error:   'Missing field: ips',
            example: { ips: ['41.58.120.5', '102.89.47.3'] }
        });
    }

    // Accept either a single string or an array
    const incoming = (Array.isArray(ips) ? ips : [ips])
        .map(ip => ip.trim())
        .filter(Boolean);

    if (incoming.length === 0) {
        return res.status(400).json({ success: false, error: 'No valid IPs provided' });
    }

    // Add only new ones (no duplicates)
    const added = [];
    for (const ip of incoming) {
        if (!allowedIps.includes(ip)) {
            allowedIps.push(ip);
            added.push(ip);
        }
    }

    console.log(`\n📋 ALLOWED IPs UPDATED — added: ${added.join(', ') || 'none (already existed)'}`);
    console.log(`   Full list: ${allowedIps.join(', ')}`);

    res.json({
        success:      true,
        added:        added,
        skipped:      incoming.filter(ip => !added.includes(ip)),
        allowed_ips:  allowedIps,
        count:        allowedIps.length
    });
});

// DELETE /allowed-ips  — remove an IP from the whitelist
// body: { "ip": "41.58.120.5" }
app.delete('/allowed-ips', (req, res) => {
    const { ip } = req.body;

    if (!ip) {
        return res.status(400).json({ success: false, error: 'Missing field: ip' });
    }

    const before = allowedIps.length;
    allowedIps   = allowedIps.filter(a => a !== ip.trim());

    if (allowedIps.length === before) {
        return res.status(404).json({ success: false, error: `IP ${ip} not found in list` });
    }

    console.log(`\n🗑️  ALLOWED IP REMOVED: ${ip}`);
    res.json({
        success:     true,
        removed:     ip,
        allowed_ips: allowedIps,
        count:       allowedIps.length
    });
});

// ============= ENDPOINT: My MAC =============
// Server cannot auto-detect MAC. Client must send it in x-mac-address header.
// Use this endpoint to confirm the server received it correctly.
app.get('/my-mac', (req, res) => {
    const mac = req.headers['x-mac-address'];
    console.log(`\n📱 MAC REQUEST — header: ${mac || 'Not provided'}`);

    if (!mac) {
        return res.status(400).json({
            success: false,
            mac:     null,
            message: 'No MAC received. Send your MAC in the x-mac-address header.',
            howToFindYourMac: {
                windows: 'Run: getmac /v   or   ipconfig /all',
                mac_os:  'Run: ifconfig en0 | grep ether',
                linux:   'Run: ip link show   or   cat /sys/class/net/eth0/address'
            }
        });
    }

    res.json({
        success: true,
        your_mac: mac.toUpperCase(),
        usage:   'Add this value to ALLOWED_MACS in your server .env to whitelist this device'
    });
});

// ============= ROOT ENDPOINT =============
app.get('/', (req, res) => {
    const networkInfo = getLocalNetworkIps();
    res.json({
        name: 'Remote Data Relay Server',
        status: 'online',
        version: '1.0.0',
        auth_mode: {
            ip_whitelist:  process.env.ALLOWED_IPS  ? 'ENABLED'  : 'DISABLED (set ALLOWED_IPS in .env)',
            mac_whitelist: process.env.ALLOWED_MACS ? 'ENABLED'  : 'DISABLED (set ALLOWED_MACS in .env)',
            server_whitelist: process.env.WHITELISTED_SERVER_IPS ? 'ENABLED' : 'DISABLED (set WHITELISTED_SERVER_IPS in .env)'
        },
        server_info: {
            local_ips: networkInfo.local_ips.map(ip => ip.address),
            primary_ip: networkInfo.primary_ip
        },
        discovery_endpoints: {
            server_ip:      'GET /server-ip   — get server local IP and check if whitelisted',
            server_network: 'GET /server-network — view all network interfaces',
            my_public_ip:   'GET /my-ip   — open in browser to find your public IP',
            my_mac:         'GET /my-mac  — send x-mac-address header to verify your MAC'
        },
        server_ip_management: {
            view:   'GET /white/s/p     — view all whitelisted server IPs',
            add:    'POST /white/s/p    — add server IPs to whitelist',
            remove: 'DELETE /white/s/p  — remove server IP from whitelist'
        },
        protected_endpoints: {
            receive_stream: 'POST /data/realtimedata',
            get_all_data:   'GET  /testresults',
            get_paginated:  'GET  /data/page?page=1&pageSize=100',
            search:         'POST /data/search',
            find_by_field:  'GET  /data/find/:field/:value',
            stats:          'GET  /data/stats',
            history:        'GET  /data/history',
            health:         'GET  /data/health'
        },
        websocket:  'ws://' + req.get('host'),
        timestamp:  new Date().toISOString()
    });
});

// ============= HEALTH CHECK =============
app.get('/data/health', (req, res) => {
    res.json({
        status:            'online',
        hasData:           latestData.records.length > 0,
        recordCount:       latestData.count,
        lastUpdate:        latestData.lastUpdate,
        connectedBranches: connectedBranches.size,
        historySize:       dataHistory.length,
        serverWhitelist:   whitelistedServerIps,
        timestamp:         new Date().toISOString()
    });
});

// ============= RECEIVE STREAM FROM LOCAL PC =============
app.post('/data/realtimedata', async (req, res) => {
    const { timestamp, records, count, source, table } = req.body;
    const sourceSecret   = req.headers['x-source-secret'];
    const expectedSecret = process.env.REMOTE_SECRET;

    console.log(`\n📡 STREAM RECEIVED at ${new Date().toISOString()}`);
    console.log(`   Records: ${count || (records && records.length) || 0}`);
    console.log(`   Source:  ${source || 'local_pc'}`);
    console.log(`   Table:   ${table  || 'unknown'}`);

    if (expectedSecret && sourceSecret !== expectedSecret) {
        console.log(`❌ Invalid secret — rejecting data`);
        return res.status(401).json({ error: 'Invalid secret' });
    }

    if (!records || records.length === 0) {
        console.log(`⚠️ No records in stream`);
        return res.json({ success: true, message: 'No data to process' });
    }

    latestData = {
        records:    records,
        lastUpdate: new Date().toISOString(),
        source:     source || 'local_pc',
        table:      table  || 'unknown',
        count:      records.length,
        receivedAt: timestamp
    };

    dataHistory.unshift({
        timestamp:   new Date().toISOString(),
        recordCount: records.length,
        source:      source || 'local_pc'
    });

    if (dataHistory.length > MAX_HISTORY) dataHistory.pop();

    console.log(`✅ Data stored: ${records.length} records`);

    const broadcastPayload = {
        type:      'live_update',
        timestamp: new Date().toISOString(),
        records:   records,
        count:     records.length,
        source:    source || 'local_pc',
        table:     table  || 'unknown'
    };

    let branchesNotified = 0;
    for (const [branchId, branchSocket] of connectedBranches) {
        branchSocket.emit('data_update', broadcastPayload);
        branchesNotified++;
    }

    console.log(`📢 Broadcast to ${branchesNotified} connected branch offices`);

    res.json({
        success:          true,
        received:         records.length,
        stored:           true,
        branchesNotified: branchesNotified,
        timestamp:        new Date().toISOString()
    });
});

// ============= BRANCH OFFICE ENDPOINTS =============
app.get('/testresults', async (req, res) => {
    console.log(`🏢 Branch requested all data`);

    if (!latestData.records || latestData.records.length === 0) {
        return res.json({
            statusCode:    200,
            statusMessage: 'successful',
            records:       [],
            message:       'No data available yet. Waiting for local PC to send data.'
        });
    }

    res.json({
        success:       true,
        statusCode:    200,
        statusMessage: 'OK',
        records:       latestData.records,
        lastUpdate:    latestData.lastUpdate,
        source:        latestData.source,
        table:         latestData.table
    });
});

app.get('/data/page', async (req, res) => {
    const page       = parseInt(req.query.page)     || 1;
    const pageSize   = Math.min(parseInt(req.query.pageSize) || 100, 1000);
    const startIndex = (page - 1) * pageSize;

    console.log(`🏢 Branch requested page ${page}, size ${pageSize}`);

    if (!latestData.records || latestData.records.length === 0) {
        return res.json({
            success: true, statusCode: 200, statusMessage: 'OK',
            records: [], total: 0, page, pageSize, totalPages: 0,
            message: 'No data available'
        });
    }

    res.json({
        success:       true,
        statusCode:    200,
        statusMessage: 'OK',
        records:       latestData.records.slice(startIndex, startIndex + pageSize),
        total:         latestData.count,
        page,
        pageSize,
        totalPages:    Math.ceil(latestData.count / pageSize),
        lastUpdate:    latestData.lastUpdate
    });
});

app.post('/data/search', async (req, res) => {
    const { filters = {}, searchTerm = null } = req.body;

    console.log(`🏢 Branch search request`);

    if (!latestData.records || latestData.records.length === 0) {
        return res.json({ success: true, records: [], count: 0, message: 'No data available' });
    }

    let results = [...latestData.records];

    if (searchTerm) {
        const term = searchTerm.toLowerCase();
        results = results.filter(record =>
            Object.values(record).some(v => String(v).toLowerCase().includes(term))
        );
    }

    if (Object.keys(filters).length > 0) {
        results = results.filter(record =>
            Object.entries(filters).every(([key, value]) =>
                String(record[key]).toLowerCase() === String(value).toLowerCase()
            )
        );
    }

    console.log(`✅ Found ${results.length} matching records`);

    res.json({
        success:    true,
        records:    results,
        count:      results.length,
        total:      latestData.count,
        searchTerm: searchTerm || null,
        filters:    Object.keys(filters).length > 0 ? filters : null
    });
});

app.get('/data/find/:field/:value', async (req, res) => {
    const { field, value } = req.params;
    console.log(`🏢 Branch searching: ${field} = ${value}`);

    if (!latestData.records || latestData.records.length === 0) {
        return res.json({ success: true, records: [], count: 0, message: 'No data available' });
    }

    const matched = latestData.records.filter(record =>
        String(record[field]).toUpperCase() === String(value).toUpperCase()
    );

    console.log(`✅ Found ${matched.length} records`);
    res.json({ success: true, records: matched, count: matched.length, field, value });
});

app.get('/data/stats', async (req, res) => {
    console.log(`🏢 Branch requested stats`);

    if (!latestData.records || latestData.records.length === 0) {
        return res.json({ success: true, hasData: false, message: 'No data available yet.' });
    }

    const columns = Object.keys(latestData.records[0] || {});
    res.json({
        success: true,
        hasData: true,
        stats: {
            totalRecords: latestData.count,
            columns,
            columnCount:  columns.length,
            lastUpdate:   latestData.lastUpdate,
            source:       latestData.source,
            table:        latestData.table
        }
    });
});

app.get('/data/history', async (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    console.log(`🏢 Branch requested history (last ${limit} updates)`);
    res.json({
        success:      true,
        history:      dataHistory.slice(0, limit),
        totalUpdates: dataHistory.length,
        currentData:  { recordCount: latestData.count, lastUpdate: latestData.lastUpdate }
    });
});

app.get('/data/export', async (req, res) => {
    console.log(`🏢 Branch requested data export`);
    if (!latestData.records || latestData.records.length === 0) {
        return res.status(404).json({ success: false, message: 'No data available to export' });
    }
    res.json({
        success:      true,
        exportedAt:   new Date().toISOString(),
        source:       latestData.source,
        table:        latestData.table,
        totalRecords: latestData.count,
        data:         latestData.records
    });
});

// ============= WEBSOCKET =============
io.on('connection', (socket) => {
    const branchId  = socket.id;
    const fwd       = socket.handshake.headers['x-forwarded-for'];
    const clientIp  = fwd ? fwd.split(',')[0].trim() : (socket.handshake.address || 'Unknown');
    const clientMac = socket.handshake.headers['x-mac-address'] || 'Not provided';

    console.log(`\n🔐 WEBSOCKET CONNECTION:`);
    console.log(`   📍 Client IP: ${clientIp}`);
    console.log(`   🖥️  MAC:       ${clientMac}`);
    console.log(`   🆔 Socket ID: ${branchId}`);

    connectedBranches.set(branchId, socket);

    if (latestData.records && latestData.records.length > 0) {
        socket.emit('connected', {
            status: 'connected', message: 'Connected to data relay server',
            recordCount: latestData.count, lastUpdate: latestData.lastUpdate, hasData: true
        });
        socket.emit('data_update', {
            type: 'initial', timestamp: new Date().toISOString(),
            records: latestData.records, count: latestData.count, source: latestData.source
        });
        console.log(`📤 Sent initial data (${latestData.count} records) to branch ${branchId}`);
    } else {
        socket.emit('connected', {
            status: 'connected',
            message: 'Connected to data relay server — waiting for data from local PC',
            hasData: false
        });
    }

    socket.on('filter_request', (filters) => {
        console.log(`🔍 Branch ${branchId} requested filter:`, filters);
        if (!latestData.records || latestData.records.length === 0) {
            socket.emit('filter_response', { records: [], count: 0, message: 'No data available' });
            return;
        }
        const filtered = latestData.records.filter(record =>
            Object.entries(filters).every(([key, value]) =>
                String(record[key]).toLowerCase().includes(String(value).toLowerCase())
            )
        );
        socket.emit('filter_response', {
            records: filtered, count: filtered.length,
            filters, timestamp: new Date().toISOString()
        });
        console.log(`📤 Sent ${filtered.length} filtered records to branch ${branchId}`);
    });

    socket.on('refresh_request', () => {
        console.log(`🔄 Branch ${branchId} requested refresh`);
        if (latestData.records && latestData.records.length > 0) {
            socket.emit('data_update', {
                type: 'refresh', timestamp: new Date().toISOString(),
                records: latestData.records, count: latestData.count, source: latestData.source
            });
        }
    });

    socket.on('ping', () => {
        socket.emit('pong', { timestamp: new Date().toISOString() });
    });

    socket.on('disconnect', () => {
        console.log(`🏢 BRANCH OFFICE DISCONNECTED: ${branchId}`);
        connectedBranches.delete(branchId);
    });
});

// ============= START SERVER =============
server.listen(PORT, () => {
    const networkInfo = getLocalNetworkIps();
    console.log(`
    ═══════════════════════════════════════════════════════
    🌐 REMOTE RELAY SERVER
    ═══════════════════════════════════════════════════════
    📍 URL:        http://localhost:${PORT}
    🖥️ Server IPs: ${networkInfo.local_ips.map(ip => ip.address).join(', ') || 'None found'}
    🔐 IP auth:    ${process.env.ALLOWED_IPS  ? 'ENABLED  → ' + process.env.ALLOWED_IPS  : 'DISABLED (set ALLOWED_IPS in .env)'}
    🔐 MAC auth:   ${process.env.ALLOWED_MACS ? 'ENABLED  → ' + process.env.ALLOWED_MACS : 'DISABLED (set ALLOWED_MACS in .env)'}
    🔐 Server IP whitelist: ${process.env.WHITELISTED_SERVER_IPS ? 'ENABLED  → ' + process.env.WHITELISTED_SERVER_IPS : 'DISABLED (set WHITELISTED_SERVER_IPS in .env)'}
    
    📡 Endpoints:
       GET  /server-ip      → check if server local IP is whitelisted
       GET  /server-network → view all network interfaces
       GET  /white/s/p      → view whitelisted server IPs
       POST /white/s/p      → add server IPs to whitelist
       DELETE /white/s/p    → remove server IP from whitelist
       GET  /my-ip          → see your public IP
       GET  /my-mac         → verify your MAC
    ═══════════════════════════════════════════════════════
    `);
});