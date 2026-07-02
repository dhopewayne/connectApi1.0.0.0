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

// ============= TRACK ALL PCs ACCESSING THE SERVER =============
// Store information about every PC that accesses the server
let pcAccessLog = new Map(); // Key: client_ip, Value: PC info

// ============= WHITELIST CONFIGURATION =============
let whitelistedStaticIps = process.env.WHITELISTED_STATIC_IPS
    ? process.env.WHITELISTED_STATIC_IPS.split(',').map(ip => ip.trim()).filter(Boolean)
    : [];

let whitelistedNetworks = process.env.WHITELISTED_NETWORKS
    ? process.env.WHILISTED_NETWORKS.split(',').map(network => network.trim()).filter(Boolean)
    : [];

// ============= LOGGING =============
app.use((req, res, next) => {
    console.log(`\n🔵 [${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
    next();
});

// ============= MIDDLEWARE: Track All PCs =============
app.use((req, res, next) => {
    const networkInfo = getClientNetworkInfo(req);
    const clientIp = networkInfo.client_ip;
    
    if (clientIp && clientIp !== 'Unknown' && clientIp !== '127.0.0.1') {
        // Check if this PC already exists
        if (!pcAccessLog.has(clientIp)) {
            // New PC detected
            pcAccessLog.set(clientIp, {
                first_seen: new Date().toISOString(),
                last_seen: new Date().toISOString(),
                total_requests: 0,
                ip_chain: networkInfo.ip_chain,
                socket_ip: networkInfo.socket.remoteAddress,
                user_agent: networkInfo.user_agent,
                host: networkInfo.host,
                is_whitelisted: false,
                request_history: []
            });
            console.log(`🆕 NEW PC DETECTED: ${clientIp}`);
        }
        
        // Update existing PC record
        const pcRecord = pcAccessLog.get(clientIp);
        pcRecord.last_seen = new Date().toISOString();
        pcRecord.total_requests += 1;
        pcRecord.ip_chain = networkInfo.ip_chain;
        pcRecord.socket_ip = networkInfo.socket.remoteAddress;
        pcRecord.user_agent = networkInfo.user_agent || pcRecord.user_agent;
        pcRecord.host = networkInfo.host || pcRecord.host;
        
        // Check if whitelisted
        pcRecord.is_whitelisted = isIpWhitelisted(clientIp);
        
        // Store request history (keep last 10)
        pcRecord.request_history.push({
            timestamp: new Date().toISOString(),
            method: req.method,
            url: req.originalUrl,
            status: 'pending'
        });
        if (pcRecord.request_history.length > 10) {
            pcRecord.request_history.shift();
        }
        
        // Update the map
        pcAccessLog.set(clientIp, pcRecord);
    }
    
    next();
});

// ============= HELPER: Get Client PC Network Information =============
function getClientNetworkInfo(req) {
    const forwarded = req.headers['x-forwarded-for'];
    const xRealIp = req.headers['x-real-ip'];
    const cfConnectingIp = req.headers['cf-connecting-ip'];
    const socketIp = req.socket?.remoteAddress || req.connection?.remoteAddress;
    
    let ipChain = [];
    if (forwarded) {
        ipChain = forwarded.split(',').map(ip => ip.trim());
    }
    
    let clientIp = null;
    if (ipChain.length > 0) {
        clientIp = ipChain[0];
    } else if (cfConnectingIp) {
        clientIp = cfConnectingIp;
    } else if (xRealIp) {
        clientIp = xRealIp;
    } else if (socketIp) {
        clientIp = socketIp;
    }
    
    if (clientIp === '::1' || clientIp === '::ffff:127.0.0.1') {
        clientIp = '127.0.0.1';
    }
    
    return {
        client_ip: clientIp || 'Unknown',
        ip_chain: ipChain,
        headers: {
            'x-forwarded-for': forwarded || null,
            'x-real-ip': xRealIp || null,
            'cf-connecting-ip': cfConnectingIp || null,
            'x-client-ip': req.headers['x-client-ip'] || null,
            'x-forwarded-host': req.headers['x-forwarded-host'] || null,
            'x-forwarded-proto': req.headers['x-forwarded-proto'] || null,
            'x-forwarded-port': req.headers['x-forwarded-port'] || null,
        },
        socket: {
            remoteAddress: socketIp || null,
            remotePort: req.socket?.remotePort || req.connection?.remotePort || null,
            localAddress: req.socket?.localAddress || req.connection?.localAddress || null,
            localPort: req.socket?.localPort || req.connection?.localPort || null,
        },
        user_agent: req.headers['user-agent'] || null,
        host: req.headers['host'] || null,
        origin: req.headers['origin'] || null,
        referer: req.headers['referer'] || null,
    };
}

// ============= HELPER: Check if IP is whitelisted =============
function isIpWhitelisted(ip) {
    if (!ip || ip === 'Unknown') return false;
    
    if (whitelistedStaticIps.includes(ip)) return true;
    
    if (whitelistedNetworks.length > 0) {
        for (const network of whitelistedNetworks) {
            if (isIpInNetwork(ip, network)) {
                return true;
            }
        }
    }
    
    return false;
}

// ============= HELPER: Check if IP is in network range =============
function isIpInNetwork(ip, cidr) {
    if (!ip || !cidr) return false;
    
    const [network, maskBits] = cidr.split('/');
    if (!network || !maskBits) return false;
    
    const ipParts = ip.split('.').map(Number);
    const networkParts = network.split('.').map(Number);
    
    if (ipParts.length !== 4 || networkParts.length !== 4) return false;
    if (ipParts.some(isNaN) || networkParts.some(isNaN)) return false;
    
    const mask = parseInt(maskBits);
    const cidrMask = ~0 << (32 - mask);
    
    const ipNum = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
    const networkNum = (networkParts[0] << 24) | (networkParts[1] << 16) | (networkParts[2] << 8) | networkParts[3];
    
    return (ipNum & cidrMask) === (networkNum & cidrMask);
}

// ============= ENDPOINT: Show All PCs Accessing the Server =============
app.get('/all-pcs', (req, res) => {
    // Convert Map to array for response
    const allPCs = [];
    let whitelistedCount = 0;
    let totalRequests = 0;
    
    for (const [ip, info] of pcAccessLog) {
        allPCs.push({
            ip: ip,
            ...info
        });
        if (info.is_whitelisted) whitelistedCount++;
        totalRequests += info.total_requests;
    }
    
    // Sort by last_seen (most recent first)
    allPCs.sort((a, b) => new Date(b.last_seen) - new Date(a.last_seen));
    
    res.json({
        success: true,
        summary: {
            total_pcs: allPCs.length,
            whitelisted_pcs: whitelistedCount,
            unwhitelisted_pcs: allPCs.length - whitelistedCount,
            total_requests: totalRequests,
            last_updated: new Date().toISOString()
        },
        pcs: allPCs,
        whitelist: {
            static_ips: whitelistedStaticIps,
            networks: whitelistedNetworks
        },
        timestamp: new Date().toISOString()
    });
});

// ============= ENDPOINT: Show Specific PC Details =============
app.get('/pc/:ip', (req, res) => {
    const ip = req.params.ip;
    
    if (!pcAccessLog.has(ip)) {
        return res.status(404).json({
            success: false,
            error: 'PC not found',
            message: `No PC with IP ${ip} has accessed this server`
        });
    }
    
    const pcInfo = pcAccessLog.get(ip);
    
    res.json({
        success: true,
        pc: {
            ip: ip,
            ...pcInfo
        },
        timestamp: new Date().toISOString()
    });
});

// ============= ENDPOINT: Clear PC Access Log =============
app.delete('/all-pcs', (req, res) => {
    const count = pcAccessLog.size;
    pcAccessLog.clear();
    
    console.log(`🗑️ PC access log cleared (${count} PCs removed)`);
    
    res.json({
        success: true,
        message: `Cleared PC access log`,
        removed_count: count,
        timestamp: new Date().toISOString()
    });
});

// ============= ENDPOINT: Show PC Network Info =============
app.get('/my-pc-check', (req, res) => {
    const networkInfo = getClientNetworkInfo(req);
    const clientIp = networkInfo.client_ip;
    
    console.log(`\n🖥️ PC CHECK from ${clientIp}`);
    console.log(`   IP Chain: ${networkInfo.ip_chain.join(' -> ')}`);
    console.log(`   Socket IP: ${networkInfo.socket.remoteAddress}`);
    
    const isWhitelisted = isIpWhitelisted(clientIp);
    const pcHistory = pcAccessLog.get(clientIp);
    
    res.json({
        success: true,
        your_pc_network_info: {
            client_ip: clientIp,
            ip_chain: networkInfo.ip_chain,
            socket: {
                remote_address: networkInfo.socket.remoteAddress,
                remote_port: networkInfo.socket.remotePort,
                local_address: networkInfo.socket.localAddress,
                local_port: networkInfo.socket.localPort
            },
            headers: networkInfo.headers,
            user_agent: networkInfo.user_agent,
            host: networkInfo.host,
            origin: networkInfo.origin,
            is_whitelisted: isWhitelisted,
            total_requests: pcHistory?.total_requests || 0,
            first_seen: pcHistory?.first_seen || null,
            last_seen: pcHistory?.last_seen || null
        },
        whitelist_status: {
            status: isWhitelisted ? '✅ AUTHORIZED' : '❌ NOT AUTHORIZED',
            message: isWhitelisted 
                ? `Your PC (${clientIp}) is authorized to access this server`
                : `Your PC (${clientIp || 'unknown'}) is NOT authorized to access this server`
        },
        server_whitelist: {
            static_ips: whitelistedStaticIps,
            networks: whitelistedNetworks
        },
        timestamp: new Date().toISOString()
    });
});

// ============= AUTHENTICATION =============
const authenticateBranch = (req, res, next) => {
    const networkInfo = getClientNetworkInfo(req);
    const clientIp = networkInfo.client_ip;
    
    console.log(`\n🔐 AUTH CHECK:`);
    console.log(`   📍 Client IP: ${clientIp}`);
    console.log(`   🔗 IP Chain: ${networkInfo.ip_chain.join(' -> ') || 'None'}`);
    
    if (!clientIp || clientIp === 'Unknown') {
        console.log(`   ❌ No IP detected`);
        return res.status(401).json({
            success: false,
            error: 'Unable to identify client IP'
        });
    }
    
    const isAuthorized = isIpWhitelisted(clientIp);
    
    if (!isAuthorized) {
        console.log(`   ❌ ACCESS DENIED`);
        return res.status(403).json({
            success: false,
            error: 'Access denied',
            reason: 'Your PC is not authorized to access this server',
            your_ip: clientIp,
            whitelisted_ips: whitelistedStaticIps,
            whitelisted_networks: whitelistedNetworks,
            how_to_fix: {
                method_1: `Add your IP to .env: WHITELISTED_STATIC_IPS=${clientIp}`,
                method_2: `POST to /whitelist/static with: { "ips": ["${clientIp}"] }`
            }
        });
    }
    
    console.log(`   ✅ ACCESS GRANTED`);
    req.networkInfo = networkInfo;
    req.clientIp = clientIp;
    next();
};

// ============= WHITELIST MANAGEMENT =============

app.get('/whitelist', (req, res) => {
    res.json({
        success: true,
        whitelist: {
            static_ips: whitelistedStaticIps,
            networks: whitelistedNetworks
        },
        counts: {
            static_ips: whitelistedStaticIps.length,
            networks: whitelistedNetworks.length
        }
    });
});

app.post('/whitelist/static', (req, res) => {
    const { ips } = req.body;
    
    if (!ips) {
        return res.status(400).json({
            success: false,
            error: 'Missing field: ips',
            example: { ips: ['192.168.1.100', '10.0.0.5'] }
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
            // Update PC record if exists
            if (pcAccessLog.has(ip)) {
                const record = pcAccessLog.get(ip);
                record.is_whitelisted = true;
                pcAccessLog.set(ip, record);
            }
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
            // Update all PC records that are in this network
            for (const [ip, record] of pcAccessLog) {
                if (isIpInNetwork(ip, network)) {
                    record.is_whitelisted = true;
                    pcAccessLog.set(ip, record);
                }
            }
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
            // Update PC record
            if (pcAccessLog.has(value)) {
                const record = pcAccessLog.get(value);
                record.is_whitelisted = false;
                pcAccessLog.set(value, record);
            }
        }
    } else if (type === 'network') {
        const index = whitelistedNetworks.indexOf(value);
        if (index !== -1) {
            whitelistedNetworks.splice(index, 1);
            removed = true;
            // Re-check all PCs
            for (const [ip, record] of pcAccessLog) {
                record.is_whitelisted = isIpWhitelisted(ip);
                pcAccessLog.set(ip, record);
            }
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
app.use('/testresults', authenticateBranch);
app.use('/data', authenticateBranch);

app.get('/testresults', (req, res) => {
    res.json({
        success: true,
        message: 'Protected endpoint - you are authenticated!',
        your_ip: req.clientIp,
        data: latestData
    });
});

app.get('/data', (req, res) => {
    res.json({
        success: true,
        message: 'Protected data endpoint',
        your_ip: req.clientIp,
        records: latestData.records || []
    });
});

app.post('/data/realtimedata', authenticateBranch, async (req, res) => {
    const { timestamp, records, count, source, table } = req.body;
    const sourceSecret = req.headers['x-source-secret'];
    const expectedSecret = process.env.REMOTE_SECRET;

    console.log(`\n📡 STREAM RECEIVED at ${new Date().toISOString()}`);
    console.log(`   Records: ${count || (records && records.length) || 0}`);
    console.log(`   Source:  ${source || 'local_pc'}`);
    console.log(`   Table:   ${table || 'unknown'}`);

    if (expectedSecret && sourceSecret !== expectedSecret) {
        console.log(`❌ Invalid secret — rejecting data`);
        return res.status(401).json({ error: 'Invalid secret' });
    }

    if (!records || records.length === 0) {
        console.log(`⚠️ No records in stream`);
        return res.json({ success: true, message: 'No data to process' });
    }

    latestData = {
        records: records,
        lastUpdate: new Date().toISOString(),
        source: source || 'local_pc',
        table: table || 'unknown',
        count: records.length,
        receivedAt: timestamp
    };

    dataHistory.unshift({
        timestamp: new Date().toISOString(),
        recordCount: records.length,
        source: source || 'local_pc'
    });

    if (dataHistory.length > MAX_HISTORY) dataHistory.pop();

    console.log(`✅ Data stored: ${records.length} records`);

    const broadcastPayload = {
        type: 'live_update',
        timestamp: new Date().toISOString(),
        records: records,
        count: records.length,
        source: source || 'local_pc',
        table: table || 'unknown'
    };

    let branchesNotified = 0;
    for (const [branchId, branchSocket] of connectedBranches) {
        branchSocket.emit('data_update', broadcastPayload);
        branchesNotified++;
    }

    console.log(`📢 Broadcast to ${branchesNotified} connected branch offices`);

    res.json({
        success: true,
        received: records.length,
        stored: true,
        branchesNotified: branchesNotified,
        timestamp: new Date().toISOString()
    });
});

// ============= ROOT ENDPOINT =============
app.get('/', (req, res) => {
    const networkInfo = getClientNetworkInfo(req);
    
    res.json({
        name: 'PC Tracking & Authentication Server',
        status: 'online',
        version: '3.0.0',
        total_pcs_tracked: pcAccessLog.size,
        your_network: {
            client_ip: networkInfo.client_ip,
            ip_chain: networkInfo.ip_chain,
            socket_ip: networkInfo.socket.remoteAddress
        },
        endpoints: {
            'GET /my-pc-check': 'Show your PC network information',
            'GET /all-pcs': 'Show ALL PCs that have accessed this server',
            'GET /pc/:ip': 'Show details for a specific PC',
            'DELETE /all-pcs': 'Clear PC access log',
            'GET /whitelist': 'View whitelist',
            'POST /whitelist/static': 'Add static IPs to whitelist',
            'POST /whitelist/network': 'Add network ranges to whitelist',
            'DELETE /whitelist': 'Remove from whitelist'
        },
        timestamp: new Date().toISOString()
    });
});

// ============= WEBSOCKET =============
io.on('connection', (socket) => {
    const branchId = socket.id;
    const fwd = socket.handshake.headers['x-forwarded-for'];
    const clientIp = fwd ? fwd.split(',')[0].trim() : (socket.handshake.address || 'Unknown');
    const clientMac = socket.handshake.headers['x-mac-address'] || 'Not provided';

    console.log(`\n🔐 WEBSOCKET CONNECTION:`);
    console.log(`   📍 Client IP: ${clientIp}`);
    console.log(`   🖥️  MAC:       ${clientMac}`);
    console.log(`   🆔 Socket ID: ${branchId}`);

    connectedBranches.set(branchId, socket);

    if (latestData.records && latestData.records.length > 0) {
        socket.emit('connected', {
            status: 'connected',
            message: 'Connected to data relay server',
            recordCount: latestData.count,
            lastUpdate: latestData.lastUpdate,
            hasData: true
        });
        socket.emit('data_update', {
            type: 'initial',
            timestamp: new Date().toISOString(),
            records: latestData.records,
            count: latestData.count,
            source: latestData.source
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
            records: filtered,
            count: filtered.length,
            filters,
            timestamp: new Date().toISOString()
        });
        console.log(`📤 Sent ${filtered.length} filtered records to branch ${branchId}`);
    });

    socket.on('refresh_request', () => {
        console.log(`🔄 Branch ${branchId} requested refresh`);
        if (latestData.records && latestData.records.length > 0) {
            socket.emit('data_update', {
                type: 'refresh',
                timestamp: new Date().toISOString(),
                records: latestData.records,
                count: latestData.count,
                source: latestData.source
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
server.listen(PORT, '0.0.0.0', () => {
    console.log(`
    ═══════════════════════════════════════════════════════
    🖥️  PC TRACKING & AUTHENTICATION SERVER
    ═══════════════════════════════════════════════════════
    📍 URL:        http://0.0.0.0:${PORT}
    
    📡 Track ALL PCs accessing this server:
       GET /all-pcs  → See every PC that has connected
    
    📋 What you'll see for each PC:
       - IP address
       - First seen / Last seen
       - Total requests made
       - IP chain (proxy path)
       - User agent
       - Whitelist status
       - Request history
    
    🔐 Authentication: IP from x-forwarded-for Header
    
    💡 Test from your PC:
       curl http://localhost:${PORT}/my-pc-check
    
    📊 View all PCs:
       curl http://localhost:${PORT}/all-pcs
    
    🔑 Add your PC to whitelist:
       curl -X POST /whitelist/static \\
         -H "Content-Type: application/json" \\
         -d '{"ips": ["YOUR_IP_HERE"]}'
    ═══════════════════════════════════════════════════════
    `);
});