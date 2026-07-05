// ============================================================
// REMOTE SERVER - PC TRACKING & AUTHENTICATION WITH WHITELIST
// ============================================================
// This server tracks all PCs that access it, maintains a whitelist,
// and protects endpoints by checking if the client IP is whitelisted.
// ============================================================

const express = require('express');
const cors = require('cors');
const http = require('http');
const socketIo = require('socket.io');
const os = require('os');
require('dotenv').config();

// ============================================================
// SECTION 1: INITIALIZATION
// ============================================================

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: { origin: '*', methods: ['GET', 'POST'] },
    pingTimeout: 60000,
    pingInterval: 25000
});

const PORT = process.env.PORT || 3000;

// ============================================================
// SECTION 2: MIDDLEWARE
// ============================================================

app.use(express.json({ limit: '50mb' }));
app.use(cors());

// ============================================================
// SECTION 3: STORAGE
// ============================================================

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

// Track all PCs accessing the server
let pcAccessLog = new Map(); // Key: client_ip, Value: PC info

// ============================================================
// SECTION 4: WHITELIST CONFIGURATION
// ============================================================

let whitelistedStaticIps = process.env.WHITELISTED_STATIC_IPS
    ? process.env.WHITELISTED_STATIC_IPS.split(',').map(ip => ip.trim()).filter(Boolean)
    : [];

let whitelistedNetworks = process.env.WHITELISTED_NETWORKS
    ? process.env.WHITELISTED_NETWORKS.split(',').map(network => network.trim()).filter(Boolean)
    : [];

// ============================================================
// SECTION 5: LOGGING MIDDLEWARE
// ============================================================

app.use((req, res, next) => {
    console.log(`\n🔵 [${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
    next();
});

// ============================================================
// SECTION 6: IP UTILITY FUNCTIONS
// ============================================================

/**
 * Get client IP from various headers
 * Handles proxies, Cloudflare, etc.
 */
function getClientIp(req) {
    // Check various headers in order of trust
    const forwarded = req.headers['x-forwarded-for'];
    const xRealIp = req.headers['x-real-ip'];
    const cfConnectingIp = req.headers['cf-connecting-ip'];
    const socketIp = req.socket?.remoteAddress || req.connection?.remoteAddress;
    
    let clientIp = null;
    let ipChain = [];
    
    // Build IP chain from x-forwarded-for
    if (forwarded) {
        ipChain = forwarded.split(',').map(ip => ip.trim());
        clientIp = ipChain[0];
    } else if (cfConnectingIp) {
        clientIp = cfConnectingIp;
    } else if (xRealIp) {
        clientIp = xRealIp;
    } else if (socketIp) {
        clientIp = socketIp;
    }
    
    // Normalize localhost
    if (clientIp === '::1' || clientIp === '::ffff:127.0.0.1') {
        clientIp = '127.0.0.1';
    }
    
    return { clientIp, ipChain, socketIp };
}

/**
 * Check if IP is in a CIDR network range
 */
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

/**
 * Check if an IP is whitelisted (static or network range)
 */
function isIpWhitelisted(ip) {
    if (!ip || ip === 'Unknown' || ip === '127.0.0.1') {
        // Localhost is always allowed for testing
        if (ip === '127.0.0.1') return true;
        return false;
    }
    
    // Check static IPs
    if (whitelistedStaticIps.includes(ip)) return true;
    
    // Check network ranges
    if (whitelistedNetworks.length > 0) {
        for (const network of whitelistedNetworks) {
            if (isIpInNetwork(ip, network)) {
                return true;
            }
        }
    }
    
    return false;
}

/**
 * Get full network info for a request
 */
function getClientNetworkInfo(req) {
    const { clientIp, ipChain, socketIp } = getClientIp(req);
    
    return {
        client_ip: clientIp || 'Unknown',
        ip_chain: ipChain || [],
        socket: {
            remoteAddress: socketIp || 'Unknown',
            remotePort: req.socket?.remotePort || 'Unknown',
            localAddress: req.socket?.localAddress || 'Unknown',
            localPort: req.socket?.localPort || 'Unknown'
        },
        headers: {
            forwarded: req.headers['x-forwarded-for'] || null,
            real_ip: req.headers['x-real-ip'] || null,
            cf_connecting_ip: req.headers['cf-connecting-ip'] || null
        },
        user_agent: req.headers['user-agent'] || 'Unknown',
        host: req.headers['host'] || 'Unknown',
        origin: req.headers['origin'] || null,
        is_whitelisted: isIpWhitelisted(clientIp)
    };
}

// ============================================================
// SECTION 7: TRACKING MIDDLEWARE
// ============================================================

/**
 * Middleware to track all PCs accessing the server
 */
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
                is_whitelisted: networkInfo.is_whitelisted,
                request_history: [],
                endpoints_accessed: []
            });
            console.log(`🆕 NEW PC DETECTED: ${clientIp} (Whitelisted: ${networkInfo.is_whitelisted})`);
        }
        
        // Update existing PC record
        const pcRecord = pcAccessLog.get(clientIp);
        pcRecord.last_seen = new Date().toISOString();
        pcRecord.total_requests += 1;
        pcRecord.ip_chain = networkInfo.ip_chain;
        pcRecord.socket_ip = networkInfo.socket.remoteAddress;
        pcRecord.user_agent = networkInfo.user_agent || pcRecord.user_agent;
        pcRecord.host = networkInfo.host || pcRecord.host;
        pcRecord.is_whitelisted = networkInfo.is_whitelisted;
        
        // Track endpoint accessed
        if (req.originalUrl) {
            const endpoint = req.originalUrl.split('?')[0];
            if (!pcRecord.endpoints_accessed.includes(endpoint)) {
                pcRecord.endpoints_accessed.push(endpoint);
            }
        }
        
        // Store request history (keep last 20)
        pcRecord.request_history.push({
            timestamp: new Date().toISOString(),
            method: req.method,
            url: req.originalUrl,
            status: 'pending'
        });
        if (pcRecord.request_history.length > 20) {
            pcRecord.request_history.shift();
        }
        
        pcAccessLog.set(clientIp, pcRecord);
    }
    
    next();
});

// ============================================================
// SECTION 8: AUTHENTICATION MIDDLEWARE
// ============================================================

/**
 * Middleware to authenticate and check whitelist
 * Returns 403 if IP is not whitelisted
 */
const authenticateBranch = async (req, res, next) => {
    const networkInfo = getClientNetworkInfo(req);
    const clientIp = networkInfo.client_ip;
    const isWhitelisted = networkInfo.is_whitelisted;
    
    // Store client IP in request for later use
    req.clientIp = clientIp;
    req.isWhitelisted = isWhitelisted;
    req.networkInfo = networkInfo;
    
    
    // Check if whitelisted
    if (!isWhitelisted) {
        console.log(`❌ ENDPOINT ACCESS DENIED`);
        
        // Update PC record with failed attempt
        if (pcAccessLog.has(clientIp)) {
            const pcRecord = pcAccessLog.get(clientIp);
            pcRecord.last_denied = new Date().toISOString();
            pcRecord.denied_count = (pcRecord.denied_count || 0) + 1;
            pcAccessLog.set(clientIp, pcRecord);
        }
        
        return res.status(403).json({
            success: false,
            error: 'Access Denied',
            message: `contact network administrator for clarification`,
            timestamp: new Date().toISOString()
        });
    }
    next();
};

// ============================================================
// SECTION 9: WHITELIST MANAGEMENT ENDPOINTS
// ============================================================

/**
 * View current whitelist
 */
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
            total_whitelisted: whitelistedStaticIps.length + whitelistedNetworks.length
        },
        timestamp: new Date().toISOString()
    });
});

/**
 * Add static IPs to whitelist
 * Supports both formats:
 * 1. { ips: ['192.168.1.100', '10.0.0.5'] }
 * 2. { ipData: [{ ipAddress: '192.168.1.100', name: 'Test' }] }
 */
app.post('/whitelist/static', (req, res) => {
    let ipsToAdd = [];
    
    // Check if the request is from the local server (ipData format)
    if (req.body.ipData && Array.isArray(req.body.ipData)) {
        // Extract IP addresses from ipData array
        ipsToAdd = req.body.ipData
            .map(item => item.ipAddress || item.ip)
            .filter(Boolean);
        
        console.log(`📥 Received IP data from local server: ${ipsToAdd.length} IPs`);
    } 
    // Check if it's the standard format
    else if (req.body.ips) {
        const ips = Array.isArray(req.body.ips) ? req.body.ips : [req.body.ips];
        ipsToAdd = ips.map(ip => ip.trim()).filter(Boolean);
    }
    
    if (ipsToAdd.length === 0) {
        return res.status(400).json({
            success: false,
            error: 'Missing field: ips or ipData',
            example: { ips: ['192.168.1.100', '10.0.0.5'] },
            example2: { ipData: [{ ipAddress: '192.168.1.100', name: 'Test' }] }
        });
    }

    const added = [];
    const alreadyExist = [];
    
    for (const ip of ipsToAdd) {
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

    console.log(`📝 Whitelist updated: Added ${added.length} static IPs`);

    res.json({
        success: true,
        added: added,
        already_existed: alreadyExist,
        static_ips: whitelistedStaticIps,
        message: `Added ${added.length} static IP(s)`,
        timestamp: new Date().toISOString()
    });
});

/**
 * Add network ranges to whitelist
 * Body: { networks: ['192.168.1.0/24', '10.0.0.0/8'] }
 */
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
        // Validate CIDR format
        if (!network.includes('/')) {
            return res.status(400).json({
                success: false,
                error: `Invalid network format: ${network}. Use CIDR format (e.g., 192.168.1.0/24)`
            });
        }
        
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

    console.log(`📝 Whitelist updated: Added ${added.length} networks`);

    res.json({
        success: true,
        added: added,
        already_existed: alreadyExist,
        networks: whitelistedNetworks,
        message: `Added ${added.length} network(s)`,
        timestamp: new Date().toISOString()
    });
});

/**
 * Remove from whitelist
 * Body: { type: 'static'|'network', value: '192.168.1.100' }
 */
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
        } else { 
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




        }

    if (!removed) {
        return res.status(404).json({
            success: false,
            error: `${type} ${value} not found in whitelist`
        });
    }

    console.log(`🗑️ Whitelist updated: Removed ${type} ${value}`);

    res.json({
        success: true,
        message: `Removed ${type} ${value}`,
        remaining: {
            static_ips: whitelistedStaticIps,
            networks: whitelistedNetworks
        },
        timestamp: new Date().toISOString()
    });
});

// ============================================================
// SECTION 10: PC TRACKING ENDPOINTS
// ============================================================

/**
 * Show ALL PCs that have accessed this server
 */
app.get('/all-pcs', (req, res) => {
    const allPCs = [];
    let whitelistedCount = 0;
    let totalRequests = 0;
    let deniedCount = 0;
    
    for (const [ip, info] of pcAccessLog) {
        allPCs.push({
            ip: ip,
            ...info
        });
        if (info.is_whitelisted) whitelistedCount++;
        totalRequests += info.total_requests;
        deniedCount += (info.denied_count || 0);
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
            total_denied: deniedCount,
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

/**
 * Show details for a specific PC
 */
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

/**
 * Clear PC access log
 */
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

/**
 * Check your own PC's network info and whitelist status
 */
app.get('/my-pc-check', (req, res) => {
    const networkInfo = getClientNetworkInfo(req);
    const clientIp = networkInfo.client_ip;
    const isWhitelisted = networkInfo.is_whitelisted;
    
    console.log(`\n🖥️ PC CHECK from ${clientIp}`);
    console.log(`   IP Chain: ${networkInfo.ip_chain.join(' -> ')}`);
    console.log(`   Whitelisted: ${isWhitelisted}`);
    
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
            last_seen: pcHistory?.last_seen || null,
            denied_count: pcHistory?.denied_count || 0
        },
        whitelist_status: {
            status: isWhitelisted ? '✅ AUTHORIZED' : '❌ NOT AUTHORIZED',
            message: isWhitelisted 
                ? `Your PC (${clientIp}) is authorized to access protected endpoints`
                : `Your PC (${clientIp || 'unknown'}) is NOT authorized to access protected endpoints`
        },
        server_whitelist: {
            static_ips: whitelistedStaticIps,
            networks: whitelistedNetworks
        },
        timestamp: new Date().toISOString()
    });
});

// ============================================================
// SECTION 11: PROTECTED ENDPOINTS
// ============================================================

/**
 * TEST RESULTS endpoint - Protected by whitelist
 * GET /testresults - Returns the latest data
 */
app.get('/testresults', authenticateBranch, (req, res) => {
    console.log(`📊 TEST RESULTS requested by ${req.clientIp}`);
    
    // Check if we have data
    if (!latestData.records || latestData.records.length === 0) {
        return res.json({
            success: true,
            message: 'No data available yet',
            data: {
                records: [],
                lastUpdate: null
            },
            timestamp: new Date().toISOString()
        });
    }
    
    res.json({
        success: true,
        message: 'data retrieved successfully',
        data: {
            records: latestData.records,
            lastUpdate: latestData.lastUpdate
        },
        timestamp: new Date().toISOString()
    });
});

/**
 * DATA endpoint - Protected by whitelist
 * GET /data - Returns all records
 */
app.get('/data', authenticateBranch, (req, res) => {
    // console.log(`📊 DATA requested by ${req.clientIp}`);
    
    res.json({
        success: true,
        message: 'Protected data endpoint',
        // your_ip: req.clientIp,
        // is_whitelisted: req.isWhitelisted,
        records: latestData.records || [],       
        timestamp: new Date().toISOString()
    });
});

/**
 * DATA endpoint - Protected by whitelist
 * POST /data/realtimedata - Receive data from local PC
 */
app.post('/data/realtimedata', async (req, res) => {
    const { timestamp, records, count, source, table } = req.body;
    const sourceSecret = req.headers['x-source-secret'];
    const expectedSecret = process.env.REMOTE_SECRET;

    console.log(`\n📡 STREAM RECEIVED at ${new Date().toISOString()}`);
    console.log(`   From IP: ${req.clientIp}`);
    console.log(`   Records: ${count || (records && records.length) || 0}`);
    console.log(`   Source:  ${source || 'local_pc'}`);
    console.log(`   Table:   ${table || 'unknown'}`);

    // Check secret (if configured)
    if (expectedSecret && sourceSecret !== expectedSecret) {
        console.log(`❌ Invalid secret — rejecting data`);
        return res.status(401).json({
            success: false,
            error: 'Invalid secret',
            your_ip: req.clientIp
        });
    }

    if (!records || records.length === 0) {
        console.log(`⚠️ No records in stream`);
        return res.json({ 
            success: true, 
            message: 'No data to process',
            your_ip: req.clientIp
        });
    }

    // Store the data
    latestData = {
        records: records,
        lastUpdate: new Date().toISOString(),
        // source: source || 'local_pc',
        // table: table || 'unknown',
        // count: records.length,
        receivedAt: timestamp || new Date().toISOString()
    };

    // Add to history
    dataHistory.unshift({
        timestamp: new Date().toISOString(),
        recordCount: records.length,
        source: source || 'local_pc',
        from_ip: req.clientIp
    });

    if (dataHistory.length > MAX_HISTORY) dataHistory.pop();

    // console.log(`✅ Data stored: ${records.length} records`);

    // Broadcast to connected branches
    const broadcastPayload = {
        type: 'live_update',
        timestamp: new Date().toISOString(),
        records: records
        // count: records.length,
        // source: source || 'local_pc',
        // table: table || 'unknown',
        // from_ip: req.clientIp
    };

    let branchesNotified = 0;
    for (const [branchId, branchSocket] of connectedBranches) {
        try {
            branchSocket.emit('data_update', broadcastPayload);
            branchesNotified++;
        } catch (err) {
            console.log(`⚠️ Failed to notify branch ${branchId}: ${err.message}`);
        }
    }

    // console.log(`📢 Broadcast to ${branchesNotified} connected branch offices`);

    res.json({
        success: true,
        received: records.length,
        stored: true,
        branchesNotified: branchesNotified,
        // your_ip: req.clientIp,
        timestamp: new Date().toISOString()
    });
});

// ============================================================
// SECTION 12: DATA HISTORY ENDPOINT
// ============================================================

/**
 * Get data history
 */
app.get('/history', authenticateBranch, (req, res) => {
    const { limit = 20 } = req.query;
    
    res.json({
        success: true,
        // your_ip: req.clientIp,
        history: dataHistory.slice(0, parseInt(limit)),
        total: dataHistory.length,
        timestamp: new Date().toISOString()
    });
});

// ============================================================
// SECTION 13: ROOT ENDPOINT
// ============================================================

app.get('/', (req, res) => {
    const networkInfo = getClientNetworkInfo(req);
    const isWhitelisted = networkInfo.is_whitelisted;
    
    res.json({
        name: 'PC Tracking & Authentication Server',
        status: 'online',
        version: '3.0.0',
        total_pcs_tracked: pcAccessLog.size,
        // your_network: {
        //     client_ip: networkInfo.client_ip,
        //     ip_chain: networkInfo.ip_chain,
        //     socket_ip: networkInfo.socket.remoteAddress,
        //     is_whitelisted: isWhitelisted
        // },
        // endpoints: {
        //     'GET /': 'Server information',
        //     'GET /my-pc-check': 'Show your PC network information',
        //     'GET /all-pcs': 'Show ALL PCs that have accessed this server',
        //     'GET /pc/:ip': 'Show details for a specific PC',
        //     'DELETE /all-pcs': 'Clear PC access log',
        //     'GET /whitelist': 'View whitelist',
        //     'POST /whitelist/static': 'Add static IPs to whitelist',
        //     'POST /whitelist/network': 'Add network ranges to whitelist',
        //     'DELETE /whitelist': 'Remove from whitelist',
        //     'GET /testresults': 'Get test results (WHITELIST PROTECTED)',
        //     'GET /data': 'Get data (WHITELIST PROTECTED)',
        //     'POST /data/realtimedata': 'Receive data stream (WHITELIST PROTECTED)',
        //     'GET /history': 'View data history (WHITELIST PROTECTED)'
        // },
        // protected_endpoints: {
        //     '/testresults': 'Requires whitelisted IP',
        //     '/data': 'Requires whitelisted IP',
        //     '/data/realtimedata': 'Requires whitelisted IP'
        // },
        timestamp: new Date().toISOString()
    });
});

// ============================================================
// SECTION 14: WEBSOCKET HANDLING
// ============================================================

io.on('connection', (socket) => {
    const branchId = socket.id;
    const fwd = socket.handshake.headers['x-forwarded-for'];
    const clientIp = fwd ? fwd.split(',')[0].trim() : (socket.handshake.address || 'Unknown');
    const clientMac = socket.handshake.headers['x-mac-address'] || 'Not provided';
    
    // Check if IP is whitelisted
    const isWhitelisted = isIpWhitelisted(clientIp);

    console.log(`\n🔐 WEBSOCKET CONNECTION:`);
    console.log(`   📍 Client IP: ${clientIp}`);
    console.log(`   🖥️  MAC:       ${clientMac}`);
    console.log(`   🆔 Socket ID: ${branchId}`);
    console.log(`   🔑 Whitelisted: ${isWhitelisted}`);

    // Store branch connection
    connectedBranches.set(branchId, socket);

    // Send connection confirmation
    socket.emit('connected', {
        status: 'connected',
        message: 'Connected to data relay server',
        client_ip: clientIp,
        is_whitelisted: isWhitelisted,
        recordCount: latestData.count || 0,
        lastUpdate: latestData.lastUpdate,
        hasData: !!(latestData.records && latestData.records.length > 0)
    });

    // Send initial data if available
    if (latestData.records && latestData.records.length > 0) {
        socket.emit('data_update', {
            type: 'initial',
            timestamp: new Date().toISOString(),
            records: latestData.records,
            count: latestData.count,
            source: latestData.source,
            table: latestData.table
        });
        console.log(`📤 Sent initial data (${latestData.count} records) to branch ${branchId}`);
    }

    // Handle filter requests
    socket.on('filter_request', (filters) => {
        console.log(`🔍 Branch ${branchId} requested filter:`, filters);
        if (!latestData.records || latestData.records.length === 0) {
            socket.emit('filter_response', { 
                records: [], 
                count: 0, 
                message: 'No data available' 
            });
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

    // Handle refresh requests
    socket.on('refresh_request', () => {
        console.log(`🔄 Branch ${branchId} requested refresh`);
        if (latestData.records && latestData.records.length > 0) {
            socket.emit('data_update', {
                type: 'refresh',
                timestamp: new Date().toISOString(),
                records: latestData.records,
                count: latestData.count,
                source: latestData.source,
                table: latestData.table
            });
        }
    });

    // Handle ping/pong
    socket.on('ping', () => {
        socket.emit('pong', { timestamp: new Date().toISOString() });
    });

    // Handle disconnection
    socket.on('disconnect', () => {
        console.log(`🏢 BRANCH OFFICE DISCONNECTED: ${branchId}`);
        connectedBranches.delete(branchId);
    });
});

// ============================================================
// SECTION 15: GRACEFUL SHUTDOWN
// ============================================================

process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down gracefully...');
    
    // Close all socket connections
    for (const [id, socket] of connectedBranches) {
        socket.disconnect();
    }
    connectedBranches.clear();
    
    // Close server
    server.close(() => {
        console.log('✅ Server closed');
        process.exit(0);
    });
});

// ============================================================
// SECTION 16: START SERVER
// ============================================================

server.listen(PORT, '0.0.0.0', () => {
    // console.log(`
    // ═══════════════════════════════════════════════════════
    // 🖥️  PC TRACKING & AUTHENTICATION SERVER
    // ═══════════════════════════════════════════════════════
    // 📍 URL:        http://0.0.0.0:${PORT}
    
    // 🔐 PROTECTED ENDPOINTS (Require Whitelist):
    //    GET  /testresults  → View test results
    //    GET  /data         → View all data
    //    POST /data/realtimedata → Receive data stream
    
    // 📡 PC TRACKING ENDPOINTS:
    //    GET  /all-pcs      → See every PC that has connected
    //    GET  /pc/:ip       → See details for a specific PC
    //    GET  /my-pc-check  → Check your own PC status
    //    DELETE /all-pcs    → Clear PC access log
    
    // 🔑 WHITELIST MANAGEMENT:
    //    GET    /whitelist           → View whitelist
    //    POST   /whitelist/static    → Add static IPs
    //    POST   /whitelist/network   → Add network ranges
    //    DELETE /whitelist           → Remove from whitelist
    
    // 💡 Test from your PC:
    //    curl http://localhost:${PORT}/my-pc-check
    
    // 📊 View all PCs:
    //    curl http://localhost:${PORT}/all-pcs
    
    // 🔑 Add your PC to whitelist:
    //    curl -X POST /whitelist/static \\
    //      -H "Content-Type: application/json" \\
    //      -d '{"ips": ["YOUR_IP_HERE"]}'
    // ═══════════════════════════════════════════════════════
    // `);


     console.log(`
    ═══════════════════════════════════════════════════════
    🖥️  PC TRACKING & AUTHENTICATION SERVER
    ═══════════════════════════════════════════════════════
    📍 URL:        http://0.0.0.0`) ;


});

// ============================================================
// END OF SERVER
// ============================================================