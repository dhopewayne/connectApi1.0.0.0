// ============================================================
// REMOTE SERVER - PC TRACKING & AUTHENTICATION WITH DATA RECOVERY
// ============================================================
// This server tracks all PCs that access it, maintains a whitelist,
// and recovers data from local server on startup.
// ============================================================

const express = require('express');
const cors = require('cors');
const http = require('http');
const socketIo = require('socket.io');
const os = require('os');
const axios = require('axios');
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

// Track ALL PCs accessing the server (historical data)
let pcAccessLog = new Map();

// Track currently active PCs (real-time connections)
let activePCs = new Map();

// Track blocked access attempts
let blockedAttempts = new Map();

// Track known local servers that can send data
let knownLocalServers = new Map();

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

function getClientIp(req) {
    const forwarded = req.headers['x-forwarded-for'];
    const xRealIp = req.headers['x-real-ip'];
    const cfConnectingIp = req.headers['cf-connecting-ip'];
    const socketIp = req.socket?.remoteAddress || req.connection?.remoteAddress;
    
    let clientIp = null;
    let ipChain = [];
    
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
    
    if (clientIp === '::1' || clientIp === '::ffff:127.0.0.1') {
        clientIp = '127.0.0.1';
    }
    
    return { clientIp, ipChain, socketIp };
}

function getServerIps() {
    const interfaces = os.networkInterfaces();
    const ips = { ipv4: [], ipv6: [] };
    
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.internal) continue;
            if (iface.family === 'IPv4') {
                ips.ipv4.push({
                    interface: name,
                    address: iface.address,
                    netmask: iface.netmask,
                    mac: iface.mac
                });
            } else if (iface.family === 'IPv6') {
                ips.ipv6.push({
                    interface: name,
                    address: iface.address,
                    netmask: iface.netmask,
                    mac: iface.mac
                });
            }
        }
    }
    
    ips.localhost = '127.0.0.1';
    ips.primary = ips.ipv4.length > 0 ? ips.ipv4[0].address : '127.0.0.1';
    return ips;
}

function getServerMacAddress() {
    const interfaces = os.networkInterfaces();
    
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.internal) continue;
            if (!iface.mac || iface.mac === '00:00:00:00:00:00') continue;
            return {
                mac: iface.mac,
                interface: name,
                family: iface.family,
                address: iface.address
            };
        }
    }
    
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.mac && iface.mac !== '00:00:00:00:00:00') {
                return {
                    mac: iface.mac,
                    interface: name,
                    family: iface.family,
                    address: iface.address,
                    internal: iface.internal
                };
            }
        }
    }
    
    return {
        mac: 'UNKNOWN',
        interface: 'unknown',
        family: 'unknown',
        address: 'unknown'
    };
}

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

function isIpWhitelisted(ip) {
    if (!ip || ip === 'Unknown' || ip === '127.0.0.1') {
        if (ip === '127.0.0.1') return true;
        return false;
    }
    
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

function getClientNetworkInfo(req) {
    const { clientIp, ipChain, socketIp } = getClientIp(req);
    const serverIps = getServerIps();
    
    return {
        client: {
            ip: clientIp || 'Unknown',
            ip_chain: ipChain || [],
            socket: {
                remoteAddress: socketIp || 'Unknown',
                remotePort: req.socket?.remotePort || 'Unknown'
            },
            user_agent: req.headers['user-agent'] || 'Unknown',
            host: req.headers['host'] || 'Unknown',
            origin: req.headers['origin'] || null,
            is_whitelisted: isIpWhitelisted(clientIp)
        },
        server: {
            primary_ip: serverIps.primary,
            all_ipv4: serverIps.ipv4,
            port: PORT,
            hostname: os.hostname()
        },
        connection_type: clientIp === '127.0.0.1' ? 'LOCAL' : 'REMOTE'
    };
}

// ============================================================
// SECTION 7: TRACKING MIDDLEWARE
// ============================================================

app.use((req, res, next) => {
    const networkInfo = getClientNetworkInfo(req);
    const clientIp = networkInfo.client.ip;
    const isWhitelisted = networkInfo.client.is_whitelisted;
    const isLocal = networkInfo.connection_type === 'LOCAL';
    
    req.clientInfo = networkInfo.client;
    req.serverInfo = networkInfo.server;
    req.connectionType = networkInfo.connection_type;
    
    if (clientIp && clientIp !== 'Unknown' && clientIp !== '127.0.0.1') {
        if (!pcAccessLog.has(clientIp)) {
            pcAccessLog.set(clientIp, {
                first_seen: new Date().toISOString(),
                last_seen: new Date().toISOString(),
                total_requests: 0,
                ip_chain: networkInfo.client.ip_chain,
                socket_ip: networkInfo.client.socket.remoteAddress,
                user_agent: networkInfo.client.user_agent,
                host: networkInfo.client.host,
                is_whitelisted: isWhitelisted,
                is_local: isLocal,
                request_history: [],
                endpoints_accessed: [],
                total_connections: 0,
                connection_type: networkInfo.connection_type
            });
            console.log(`🆕 NEW ${isLocal ? 'LOCAL' : 'REMOTE'} CLIENT DETECTED: ${clientIp}`);
        }
        
        const pcRecord = pcAccessLog.get(clientIp);
        pcRecord.last_seen = new Date().toISOString();
        pcRecord.total_requests += 1;
        pcRecord.ip_chain = networkInfo.client.ip_chain;
        pcRecord.socket_ip = networkInfo.client.socket.remoteAddress;
        pcRecord.user_agent = networkInfo.client.user_agent || pcRecord.user_agent;
        pcRecord.host = networkInfo.client.host || pcRecord.host;
        pcRecord.is_whitelisted = isWhitelisted;
        pcRecord.is_local = isLocal;
        pcRecord.connection_type = networkInfo.connection_type;
        
        if (req.originalUrl) {
            const endpoint = req.originalUrl.split('?')[0];
            if (!pcRecord.endpoints_accessed.includes(endpoint)) {
                pcRecord.endpoints_accessed.push(endpoint);
            }
        }
        
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
        
        if (!activePCs.has(clientIp)) {
            const socketId = req.socket?.id || 'http';
            activePCs.set(clientIp, {
                connected_at: new Date().toISOString(),
                last_seen: new Date().toISOString(),
                socket_ids: [socketId],
                ip_chain: networkInfo.client.ip_chain,
                user_agent: networkInfo.client.user_agent,
                is_whitelisted: isWhitelisted,
                is_local: isLocal,
                connection_type: networkInfo.connection_type,
                requests_in_session: 1,
                server_info: networkInfo.server
            });
            console.log(`✅ ${isLocal ? 'LOCAL' : 'REMOTE'} CLIENT CONNECTED: ${clientIp}`);
            broadcastActivePCs();
        } else {
            const activeRecord = activePCs.get(clientIp);
            activeRecord.last_seen = new Date().toISOString();
            activeRecord.requests_in_session += 1;
            activeRecord.ip_chain = networkInfo.client.ip_chain;
            activeRecord.user_agent = networkInfo.client.user_agent;
            activeRecord.is_whitelisted = isWhitelisted;
            activeRecord.is_local = isLocal;
            activeRecord.connection_type = networkInfo.connection_type;
            activeRecord.server_info = networkInfo.server;
            
            const socketId = req.socket?.id || 'http';
            if (!activeRecord.socket_ids.includes(socketId)) {
                activeRecord.socket_ids.push(socketId);
            }
            
            activePCs.set(clientIp, activeRecord);
        }
    }
    
    next();
});

// ============================================================
// SECTION 8: AUTHENTICATION MIDDLEWARE
// ============================================================

const authenticateBranch = async (req, res, next) => {
    const clientIp = req.clientInfo?.ip || 'Unknown';
    const isWhitelisted = req.clientInfo?.is_whitelisted || false;
    const connectionType = req.connectionType || 'UNKNOWN';
    const endpoint = req.originalUrl;
    
    if (!isWhitelisted) {
        console.log(`❌ ACCESS DENIED - IP: ${clientIp} (${connectionType}) attempted to access ${endpoint}`);
        
        if (!blockedAttempts.has(clientIp)) {
            blockedAttempts.set(clientIp, {
                attempts: 0,
                first_blocked: new Date().toISOString(),
                last_blocked: new Date().toISOString(),
                endpoints: []
            });
        }
        
        const blockedRecord = blockedAttempts.get(clientIp);
        blockedRecord.attempts += 1;
        blockedRecord.last_blocked = new Date().toISOString();
        if (!blockedRecord.endpoints.includes(endpoint)) {
            blockedRecord.endpoints.push(endpoint);
        }
        blockedAttempts.set(clientIp, blockedRecord);
        
        if (pcAccessLog.has(clientIp)) {
            const pcRecord = pcAccessLog.get(clientIp);
            pcRecord.last_denied = new Date().toISOString();
            pcRecord.denied_count = (pcRecord.denied_count || 0) + 1;
            pcRecord.denied_endpoints = pcRecord.denied_endpoints || [];
            if (!pcRecord.denied_endpoints.includes(endpoint)) {
                pcRecord.denied_endpoints.push(endpoint);
            }
            pcAccessLog.set(clientIp, pcRecord);
        }
        
        return res.status(403).json({
            success: false,
            error: 'Access Denied - IP Not Whitelisted',
            message: `Your IP address (${clientIp}) is not whitelisted.`,
            details: {
                your_ip: clientIp,
                connection_type: connectionType,
                endpoint_attempted: endpoint,
                timestamp: new Date().toISOString(),
                attempt_count: blockedRecord.attempts
            },
            action_required: 'Contact Network Administrator or IT Office',
            how_to_fix: {
                contact: 'Network Administrator / IT Department',
                provide: `Your IP address: ${clientIp}`,
                whitelist_endpoint: 'POST /whitelist/static'
            },
            timestamp: new Date().toISOString()
        });
    }
    
    console.log(`✅ ACCESS GRANTED - IP: ${clientIp} (${connectionType}) accessing ${endpoint}`);
    next();
};
 


// Add to remote server

/**
 * Register local server
 */
app.post('/register-local-server', (req, res) => {
    const { serverUrl, secret } = req.body;
    
    if (!serverUrl) {
        return res.status(400).json({
            success: false,
            error: 'serverUrl is required'
        });
    }
    
    // Store the registration
    knownLocalServers.set(serverUrl, {
        lastSeen: new Date().toISOString(),
        status: 'registered',
        secret: secret || null,
        registeredAt: new Date().toISOString()
    });
    
    console.log(`📝 Local server registered: ${serverUrl}`);
    
    res.json({
        success: true,
        message: 'Local server registered',
        serverUrl: serverUrl,
        timestamp: new Date().toISOString()
    });
});

/**
 * Get all registered local servers
 */
app.get('/local-servers', (req, res) => {
    const servers = [];
    for (const [url, info] of knownLocalServers) {
        servers.push({ url, ...info });
    }
    
    res.json({
        success: true,
        servers: servers,
        count: servers.length,
        timestamp: new Date().toISOString()
    });
});

/**
 * Get current data status
 */
app.get('/data-status', (req, res) => {
    res.json({
        success: true,
        data: {
            recordCount: latestData.records?.length || 0,
            lastUpdate: latestData.lastUpdate,
            source: latestData.source,
            historyCount: dataHistory.length,
            activeClients: activePCs.size            
        },
        timestamp: new Date().toISOString()
    });
});
// ============================================================
// SECTION 9: WHITELIST MANAGEMENT ENDPOINTS
// ============================================================

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

app.get('/blocked-attempts', (req, res) => {
    const blockedList = [];
    for (const [ip, info] of blockedAttempts) {
        blockedList.push({ ip, ...info });
    }
    blockedList.sort((a, b) => new Date(b.last_blocked) - new Date(a.last_blocked));
    
    res.json({
        success: true,
        total_blocked_ips: blockedList.length,
        blocked_attempts: blockedList,
        timestamp: new Date().toISOString()
    });
});

app.post('/whitelist/static', (req, res) => {
    let ipsToAdd = [];
    
    if (req.body.ipData && Array.isArray(req.body.ipData)) {
        ipsToAdd = req.body.ipData.map(item => item.ipAddress || item.ip).filter(Boolean);
        console.log(`📥 Received IP data: ${ipsToAdd.length} IPs`);
    } else if (req.body.ips) {
        const ips = Array.isArray(req.body.ips) ? req.body.ips : [req.body.ips];
        ipsToAdd = ips.map(ip => ip.trim()).filter(Boolean);
    }
    
    if (ipsToAdd.length === 0) {
        return res.status(400).json({
            success: false,
            error: 'Missing field: ips or ipData',
            example: { ips: ['192.168.1.100', '10.0.0.5'] }
        });
    }

    const added = [];
    const alreadyExist = [];
    
    for (const ip of ipsToAdd) {
        if (!whitelistedStaticIps.includes(ip)) {
            whitelistedStaticIps.push(ip);
            added.push(ip);
            if (pcAccessLog.has(ip)) {
                const record = pcAccessLog.get(ip);
                record.is_whitelisted = true;
                pcAccessLog.set(ip, record);
            }
            if (activePCs.has(ip)) {
                const activeRecord = activePCs.get(ip);
                activeRecord.is_whitelisted = true;
                activePCs.set(ip, activeRecord);
            }
            if (blockedAttempts.has(ip)) {
                blockedAttempts.delete(ip);
                console.log(`✅ IP ${ip} removed from blocked list`);
            }
        } else {
            alreadyExist.push(ip);
        }
    }

    console.log(`📝 Whitelist updated: Added ${added.length} static IPs`);
    broadcastActivePCs();

    res.json({
        success: true,
        added: added,
        already_existed: alreadyExist,
        static_ips: whitelistedStaticIps,
        message: `Added ${added.length} static IP(s)`,
        timestamp: new Date().toISOString()
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
        if (!network.includes('/')) {
            return res.status(400).json({
                success: false,
                error: `Invalid network format: ${network}. Use CIDR format`
            });
        }
        
        if (!whitelistedNetworks.includes(network)) {
            whitelistedNetworks.push(network);
            added.push(network);
            for (const [ip, record] of pcAccessLog) {
                if (isIpInNetwork(ip, network)) {
                    record.is_whitelisted = true;
                    pcAccessLog.set(ip, record);
                    if (blockedAttempts.has(ip)) {
                        blockedAttempts.delete(ip);
                    }
                }
            }
            for (const [ip, record] of activePCs) {
                if (isIpInNetwork(ip, network)) {
                    record.is_whitelisted = true;
                    activePCs.set(ip, record);
                }
            }
        } else {
            alreadyExist.push(network);
        }
    }

    console.log(`📝 Whitelist updated: Added ${added.length} networks`);
    broadcastActivePCs();

    res.json({
        success: true,
        added: added,
        already_existed: alreadyExist,
        networks: whitelistedNetworks,
        message: `Added ${added.length} network(s)`,
        timestamp: new Date().toISOString()
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
            if (pcAccessLog.has(value)) {
                const record = pcAccessLog.get(value);
                record.is_whitelisted = false;
                pcAccessLog.set(value, record);
            }
            if (activePCs.has(value)) {
                const record = activePCs.get(value);
                record.is_whitelisted = false;
                activePCs.set(value, record);
            }
        }
    } else if (type === 'network') {
        const index = whitelistedNetworks.indexOf(value);
        if (index !== -1) {
            whitelistedNetworks.splice(index, 1);
            removed = true;
            for (const [ip, record] of pcAccessLog) {
                record.is_whitelisted = isIpWhitelisted(ip);
                pcAccessLog.set(ip, record);
            }
            for (const [ip, record] of activePCs) {
                record.is_whitelisted = isIpWhitelisted(ip);
                activePCs.set(ip, record);
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
    broadcastActivePCs();

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
// SECTION 10: DATA RECOVERY ENDPOINTS
// ============================================================

/**
 * Register a local server that can send data
 */
app.post('/register-local-server', (req, res) => {
    const { serverUrl, secret } = req.body;
    
    if (!serverUrl) {
        return res.status(400).json({
            success: false,
            error: 'serverUrl is required'
        });
    }
    
    knownLocalServers.set(serverUrl, {
        lastSeen: new Date().toISOString(),
        status: 'registered',
        secret: secret || null
    });
    
    console.log(`📝 Local server registered: ${serverUrl}`);
    
    res.json({
        success: true,
        message: 'Local server registered',
        serverUrl: serverUrl,
        timestamp: new Date().toISOString()
    });
});

/**
 * Get all registered local servers
 */
app.get('/local-servers', (req, res) => {
    const servers = [];
    for (const [url, info] of knownLocalServers) {
        servers.push({ url, ...info });
    }
    
    res.json({
        success: true,
        servers: servers,
        count: servers.length,
        timestamp: new Date().toISOString()
    });
});

/**
 * REQUEST DATA RECOVERY FROM LOCAL SERVER
 * This tells the local server to resend all its data
 */
app.post('/recover-data/:serverUrl', async (req, res) => {
    const serverUrl = decodeURIComponent(req.params.serverUrl);
    const secret = req.headers['x-source-secret'] || process.env.REMOTE_SECRET;
    
    console.log(`🔄 Requesting data recovery from: ${serverUrl}`);
    
    try {
        if (!knownLocalServers.has(serverUrl)) {
            return res.status(404).json({
                success: false,
                error: 'Server not registered. Register first using /register-local-server'
            });
        }
        
        // Call the local server's recovery endpoint
        const response = await axios.post(`${serverUrl}/recovery/full`, {
            secret: secret
        }, {
            headers: {
                'Content-Type': 'application/json',
                'X-Source-Secret': secret
            },
            timeout: 30000
        });
        
        if (response.data && response.data.success) {
            console.log(`✅ Data recovery from ${serverUrl} successful`);
            
            const serverInfo = knownLocalServers.get(serverUrl);
            serverInfo.lastRecovery = new Date().toISOString();
            serverInfo.lastStatus = 'success';
            knownLocalServers.set(serverUrl, serverInfo);
            
            return res.json({
                success: true,
                message: 'Data recovery successful',
                recovered: response.data,
                serverUrl: serverUrl,
                timestamp: new Date().toISOString()
            });
        } else {
            return res.json({
                success: false,
                error: 'Recovery failed',
                message: response.data?.message || 'Unknown error',
                serverUrl: serverUrl,
                timestamp: new Date().toISOString()
            });
        }
        
    } catch (err) {
        console.error(`❌ Error recovering from ${serverUrl}:`, err.message);
        
        if (knownLocalServers.has(serverUrl)) {
            const serverInfo = knownLocalServers.get(serverUrl);
            serverInfo.lastRecovery = new Date().toISOString();
            serverInfo.lastStatus = 'failed';
            serverInfo.lastError = err.message;
            knownLocalServers.set(serverUrl, serverInfo);
        }
        
        return res.status(500).json({
            success: false,
            error: 'Recovery failed',
            message: err.message,
            serverUrl: serverUrl,
            timestamp: new Date().toISOString()
        });
    }
});

/**
 * AUTO-RECOVER from ALL registered local servers on startup
 */
app.post('/recover-all', async (req, res) => {
    console.log('🔄 Starting full recovery from all registered local servers...');
    
    const results = [];
    let totalRecovered = 0;
    let totalRecords = 0;
    
    for (const [serverUrl, info] of knownLocalServers) {
        console.log(`📤 Recovering from ${serverUrl}...`);
        
        try {
            const response = await axios.post(`${serverUrl}/recovery/full`, {}, {
                headers: {
                    'Content-Type': 'application/json',
                    'X-Source-Secret': process.env.REMOTE_SECRET
                },
                timeout: 30000
            });
            
            if (response.data && response.data.success) {
                results.push({
                    serverUrl: serverUrl,
                    success: true,
                    data: response.data
                });
                totalRecovered++;
                
                // Store the recovered data
                if (response.data.result && response.data.result.recoveryResult) {
                    const recoveredCount = response.data.result.recoveryResult.recovered || 0;
                    totalRecords += recoveredCount;
                    console.log(`✅ Recovered ${recoveredCount} records from ${serverUrl}`);
                }
            } else {
                results.push({
                    serverUrl: serverUrl,
                    success: false,
                    error: response.data?.message || 'Unknown error'
                });
                console.log(`⚠️ Failed to recover from ${serverUrl}`);
            }
        } catch (err) {
            results.push({
                serverUrl: serverUrl,
                success: false,
                error: err.message
            });
            console.log(`❌ Error recovering from ${serverUrl}: ${err.message}`);
        }
    }
    
    res.json({
        success: true,
        message: `Recovered from ${totalRecovered}/${knownLocalServers.size} servers`,
        results: results,
        total_recovered: totalRecovered,
        total_records: totalRecords,
        total_servers: knownLocalServers.size,
        timestamp: new Date().toISOString()
    });
});

/**
 * GET current data (for debugging)
 */
app.get('/current-data', authenticateBranch, (req, res) => {
    res.json({
        success: true,
        data: latestData,
        history: dataHistory,
        timestamp: new Date().toISOString()
    });
});

// ============================================================
// SECTION 11: PROTECTED ENDPOINTS
// ============================================================

// Update the remote server's /testresults endpoint to show ALL records

/**
 * TEST RESULTS endpoint - Protected by whitelist
 * GET /testresults - Returns ALL test results (Pass AND Fail)
 * Optional query params: ?status=Pass|Fail|All
 */
app.get('/testresults', authenticateBranch, (req, res) => {
    console.log(`📊 TEST RESULTS requested by ${req.clientInfo?.ip}`);
    
    const { status = 'All' } = req.query;
    
    if (!latestData.records || latestData.records.length === 0) {
        return res.json({
            success: true,
            message: 'No data available yet',
            data: {
                records: [],
                lastUpdate: null,
                summary: {
                    total: 0,
                    pass: 0,
                    fail: 0,
                    pending: 0
                }
            },
            timestamp: new Date().toISOString()
        });
    }
    
    let filteredRecords = latestData.records;
    
    // Filter by status if requested
    if (status !== 'All') {
        filteredRecords = latestData.records.filter(record => {
            const result = record.PhysicalInspectionResults?.OverallResults || 'Pending';
            return result.toLowerCase() === status.toLowerCase();
        });
    }
    
    // Calculate summary statistics
    const summary = {
        total: latestData.records.length,
        pass: latestData.records.filter(r => {
            const result = r.PhysicalInspectionResults?.OverallResults || 'Pending';
            return result.toLowerCase() === 'pass';
        }).length,
        fail: latestData.records.filter(r => {
            const result = r.PhysicalInspectionResults?.OverallResults || 'Pending';
            return result.toLowerCase() === 'fail';
        }).length,
        pending: latestData.records.filter(r => {
            const result = r.PhysicalInspectionResults?.OverallResults || 'Pending';
            return result.toLowerCase() === 'pending';
        }).length
    };
    
    res.json({
        success: true,
        message: `Data retrieved successfully`,
        filters: {
            status: status,
            available: ['All', 'Pass', 'Fail', 'Pending']
        },
        summary: summary,
        data: {
            records: filteredRecords,
            count: filteredRecords.length,
            lastUpdate: latestData.lastUpdate
        },
        timestamp: new Date().toISOString()
    });
}); 

/**
 * GET ALL TEST RESULTS - No filtering
 */
app.get('/all-testresults', authenticateBranch, (req, res) => {
    console.log(`📊 ALL TEST RESULTS requested by ${req.clientInfo?.ip}`);
    
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
    
    // Group by status
    const passRecords = latestData.records.filter(r => {
        const result = r.PhysicalInspectionResults?.OverallResults || 'Pending';
        return result.toLowerCase() === 'pass';
    });
    
    const failRecords = latestData.records.filter(r => {
        const result = r.PhysicalInspectionResults?.OverallResults || 'Pending';
        return result.toLowerCase() === 'fail';
    });
    
    const pendingRecords = latestData.records.filter(r => {
        const result = r.PhysicalInspectionResults?.OverallResults || 'Pending';
        return result.toLowerCase() === 'pending';
    });
    
    res.json({
        success: true,
        message: 'All test results retrieved',
        summary: {
            total: latestData.records.length,
            pass: passRecords.length,
            fail: failRecords.length,
            pending: pendingRecords.length
        },
        data: {
            all: latestData.records,
            pass: passRecords,
            fail: failRecords,
            pending: pendingRecords
        },
        lastUpdate: latestData.lastUpdate,
        timestamp: new Date().toISOString()
    });
}); 



/**
 * DATA endpoint - Protected by whitelist
 */
app.get('/data', authenticateBranch, (req, res) => {
    res.json({
        success: true,
        message: 'Protected data endpoint',
        records: latestData.records || [],
        count: latestData.records?.length || 0,
        lastUpdate: latestData.lastUpdate,
        source: latestData.source,
        table: latestData.table,
        timestamp: new Date().toISOString()
    });
});

/**
 * DATA endpoint - Receive data from local PC
 * POST /data/realtimedata
 * This is where the local server sends data
 */
// Add to remote server - This endpoint doesn't require whitelist for local servers
// Special endpoint for local servers to send data (bypasses whitelist check)

app.post('/data/realtimedata', async (req, res) => {
    const { timestamp, records, count, source, table, plateNumber, isRefresh } = req.body;
    const sourceSecret = req.headers['x-source-secret'];
    const expectedSecret = process.env.REMOTE_SECRET;

    console.log(`\n📡 STREAM RECEIVED at ${new Date().toISOString()}`);
    console.log(`   Records: ${count || (records && records.length) || 0}`);
    console.log(`   Source:  ${source || 'local_pc'}`);
    console.log(`   Plate:   ${plateNumber || 'N/A'}`);

    // Check secret
    if (expectedSecret && sourceSecret !== expectedSecret) {
        console.log(`❌ Invalid secret — rejecting data`);
        return res.status(401).json({
            success: false,
            error: 'Invalid secret',
            your_ip: req.ip
        });
    }

    if (!records || records.length === 0) {
        console.log(`⚠️ No records in stream`);
        return res.json({ 
            success: true, 
            message: 'No data to process'
        });
    }

    // Store the data
    latestData = {
        records: records,
        lastUpdate: new Date().toISOString(),
        source: source || 'local_pc',
        table: table || 'unknown',
        count: records.length,
        receivedAt: timestamp || new Date().toISOString()
    };

    // Add to history
    dataHistory.unshift({
        timestamp: new Date().toISOString(),
        recordCount: records.length,
        source: source || 'local_pc',
        from_ip: req.ip || 'unknown',
        plateNumber: plateNumber || 'N/A',
        isRefresh: isRefresh || false
    });

    if (dataHistory.length > MAX_HISTORY) dataHistory.pop();

    console.log(`✅ Data stored: ${records.length} records`);

    // Broadcast to connected branches
    const broadcastPayload = {
        type: 'live_update',
        timestamp: new Date().toISOString(),
        records: records,
        count: records.length,
        source: source || 'local_pc',
        plateNumber: plateNumber || null
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

    res.json({
        success: true,
        received: records.length,
        stored: true,
        branchesNotified: branchesNotified,
        timestamp: new Date().toISOString()
    });
});

/**
 * HISTORY endpoint - Protected by whitelist
 */
app.get('/history', authenticateBranch, (req, res) => {
    const { limit = 20 } = req.query;
    
    res.json({
        success: true,
        history: dataHistory.slice(0, parseInt(limit)),
        total: dataHistory.length,
        timestamp: new Date().toISOString()
    });
});

// ============================================================
// SECTION 12: PC TRACKING ENDPOINTS
// ============================================================

app.get('/all-pcs', (req, res) => {
    const activePCsList = [];
    let whitelistedCount = 0;
    let localCount = 0;
    let remoteCount = 0;
    
    for (const [ip, info] of activePCs) {
        activePCsList.push({ ip, ...info });
        if (info.is_whitelisted) whitelistedCount++;
        if (info.is_local) localCount++;
        else remoteCount++;
    }
    
    activePCsList.sort((a, b) => new Date(b.last_seen) - new Date(a.last_seen));
    
    res.json({
        success: true,
        type: 'real-time',
        summary: {
            active_clients: activePCs.size,
            whitelisted_active: whitelistedCount,
            unwhitelisted_active: activePCs.size - whitelistedCount,
            local_active: localCount,
            remote_active: remoteCount,
            last_updated: new Date().toISOString()
        },
        active_clients: activePCsList,
        server_info: {
            primary_ip: getServerIps().primary,
            port: PORT,
            hostname: os.hostname()
        },
        timestamp: new Date().toISOString()
    });
});

app.get('/all-pcs-history', (req, res) => {
    const allPCs = [];
    let whitelistedCount = 0;
    let totalRequests = 0;
    let deniedCount = 0;
    let localCount = 0;
    let remoteCount = 0;
    
    for (const [ip, info] of pcAccessLog) {
        allPCs.push({ ip, ...info });
        if (info.is_whitelisted) whitelistedCount++;
        if (info.is_local) localCount++;
        else remoteCount++;
        totalRequests += info.total_requests;
        deniedCount += (info.denied_count || 0);
    }
    
    allPCs.sort((a, b) => new Date(b.last_seen) - new Date(a.last_seen));
    
    res.json({
        success: true,
        type: 'historical',
        summary: {
            total_clients_ever: allPCs.length,
            whitelisted_clients: whitelistedCount,
            unwhitelisted_clients: allPCs.length - whitelistedCount,
            local_connections: localCount,
            remote_connections: remoteCount,
            total_requests: totalRequests,
            total_denied: deniedCount,
            last_updated: new Date().toISOString()
        },
        clients: allPCs,
        timestamp: new Date().toISOString()
    });
});

// ============================================================
// SECTION 13: BROADCAST FUNCTIONS
// ============================================================

function broadcastActivePCs() {
    const activePCsList = [];
    for (const [ip, info] of activePCs) {
        activePCsList.push({ ip, ...info });
    }
    
    const payload = {
        type: 'active_clients_update',
        timestamp: new Date().toISOString(),
        active_clients: activePCsList,
        count: activePCsList.length,
        local_count: activePCsList.filter(c => c.is_local).length,
        remote_count: activePCsList.filter(c => !c.is_local).length
    };
    
    for (const [branchId, branchSocket] of connectedBranches) {
        try {
            branchSocket.emit('active_clients_update', payload);
        } catch (err) {
            console.log(`⚠️ Failed to broadcast active clients to ${branchId}: ${err.message}`);
        }
    }
}

// ============================================================
// SECTION 14: ROOT ENDPOINT
// ============================================================

app.get('/', (req, res) => {
    const serverIps = getServerIps();
    
    res.json({
        name: 'Remote Server - Data Relay & Authentication',
        status: 'online',
        version: '3.0.0',
        server_info: {
            primary_ip: serverIps.primary,
            all_ipv4: serverIps.ipv4,
            port: PORT,
            hostname: os.hostname()
        },
        statistics: {
            total_clients_ever: pcAccessLog.size,
            active_clients: activePCs.size,
            blocked_ips: blockedAttempts.size,
            local_active: [...activePCs.values()].filter(c => c.is_local).length,
            remote_active: [...activePCs.values()].filter(c => !c.is_local).length,
            data_records: latestData.records?.length || 0,
            known_local_servers: knownLocalServers.size
        },
        protected_endpoints: {
            '/testresults': 'Requires whitelisted IP',
            '/data': 'Requires whitelisted IP',
            '/data/realtimedata': 'Requires whitelisted IP',
            '/history': 'Requires whitelisted IP'
        },
        data_recovery: {
            endpoint: '/recover-all',
            description: 'Recover data from all registered local servers',
            registered_servers: Array.from(knownLocalServers.keys())
        },
        timestamp: new Date().toISOString()
    });
});

// ============================================================
// SECTION 15: WEBSOCKET HANDLING
// ============================================================

io.on('connection', (socket) => {
    const branchId = socket.id;
    const fwd = socket.handshake.headers['x-forwarded-for'];
    const clientIp = fwd ? fwd.split(',')[0].trim() : (socket.handshake.address || 'Unknown');
    const isWhitelisted = isIpWhitelisted(clientIp);

    console.log(`\n🔐 WEBSOCKET CONNECTION:`);
    console.log(`   📍 Client IP: ${clientIp}`);
    console.log(`   🆔 Socket ID: ${branchId}`);
    console.log(`   🔑 Whitelisted: ${isWhitelisted}`);

    if (!isWhitelisted && clientIp !== '127.0.0.1') {
        console.log(`❌ WEBSOCKET CONNECTION REJECTED: ${clientIp} not whitelisted`);
        socket.emit('error', {
            error: 'Connection Rejected',
            message: `Your IP (${clientIp}) is not whitelisted.`,
            timestamp: new Date().toISOString()
        });
        socket.disconnect();
        return;
    }

    connectedBranches.set(branchId, socket);

    socket.emit('connected', {
        status: 'connected',
        message: 'Connected to data relay server',
        client_ip: clientIp,
        is_whitelisted: isWhitelisted,
        recordCount: latestData.count || 0,
        lastUpdate: latestData.lastUpdate,
        hasData: !!(latestData.records && latestData.records.length > 0),
        active_clients: activePCs.size,
        server_info: {
            primary_ip: getServerIps().primary,
            port: PORT,
            hostname: os.hostname()
        }
    });

    // Send initial data if available
    if (latestData.records && latestData.records.length > 0) {
        socket.emit('data_update', {
            type: 'initial',
            timestamp: new Date().toISOString(),
            records: latestData.records,
            count: latestData.count,
            source: latestData.source
        });
        console.log(`📤 Sent initial data (${latestData.count} records) to client ${branchId}`);
    }

    // Send active clients
    const initialActiveClients = [];
    for (const [ip, info] of activePCs) {
        initialActiveClients.push({ ip, ...info });
    }
    socket.emit('active_clients_update', {
        type: 'initial',
        timestamp: new Date().toISOString(),
        active_clients: initialActiveClients,
        count: initialActiveClients.length
    });

    socket.on('filter_request', (filters) => {
        console.log(`🔍 Client ${branchId} requested filter:`, filters);
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
        console.log(`📤 Sent ${filtered.length} filtered records to client ${branchId}`);
    });

    socket.on('refresh_request', () => {
        console.log(`🔄 Client ${branchId} requested refresh`);
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
        console.log(`🏢 CLIENT DISCONNECTED: ${branchId} (${clientIp})`);
        connectedBranches.delete(branchId);
        
        let removedCount = 0;
        for (const [ip, info] of activePCs) {
            const socketIds = info.socket_ids.filter(id => id !== branchId);
            if (socketIds.length === 0) {
                activePCs.delete(ip);
                removedCount++;
                console.log(`🔌 CLIENT DISCONNECTED: ${ip}`);
            } else {
                info.socket_ids = socketIds;
                activePCs.set(ip, info);
            }
        }
        
        if (removedCount > 0) {
            console.log(`📊 ${removedCount} clients disconnected`);
            broadcastActivePCs();
        }
    });
});

// ============================================================
// SECTION 16: AUTO-RECOVERY ON STARTUP
// ============================================================

/**
 * Auto-recover data from local servers when remote server starts
 * This ensures data is not lost even after remote server restart
 */
async function autoRecoverOnStartup() {
    console.log('🔄 Running auto-recovery on startup...');
    
    // Wait a bit for the server to fully start
    setTimeout(async () => {
        try {
            // First, check if we have any registered local servers
            if (knownLocalServers.size === 0) {
                console.log('ℹ️ No local servers registered yet. Data recovery will be attempted when a local server registers.');
                
                // Set up a listener for when a local server registers
                app.post('/register-local-server', async (req, res) => {
                    // This is the existing endpoint, but we want to trigger recovery after registration
                    const { serverUrl, secret } = req.body;
                    
                    if (!serverUrl) {
                        return res.status(400).json({
                            success: false,
                            error: 'serverUrl is required'
                        });
                    }
                    
                    knownLocalServers.set(serverUrl, {
                        lastSeen: new Date().toISOString(),
                        status: 'registered',
                        secret: secret || null
                    });
                    
                    console.log(`📝 Local server registered: ${serverUrl}`);
                    
                    // Auto-recover from this server immediately
                    console.log(`🔄 Auto-recovering data from newly registered server: ${serverUrl}`);
                    
                    try {
                        const response = await axios.post(`${serverUrl}/recovery/full`, {
                            secret: secret
                        }, {
                            headers: {
                                'Content-Type': 'application/json',
                                'X-Source-Secret': secret || process.env.REMOTE_SECRET
                            },
                            timeout: 30000
                        });
                        
                        if (response.data && response.data.success) {
                            console.log(`✅ Auto-recovery successful from ${serverUrl}`);
                            
                            // Update the data
                            if (response.data.result && response.data.result.recoveryResult) {
                                const recoveredCount = response.data.result.recoveryResult.recovered || 0;
                                console.log(`📊 Recovered ${recoveredCount} records from ${serverUrl}`);
                            }
                        } else {
                            console.log(`⚠️ Auto-recovery from ${serverUrl} failed: ${response.data?.message || 'Unknown error'}`);
                        }
                    } catch (err) {
                        console.log(`⚠️ Auto-recovery from ${serverUrl} failed: ${err.message}`);
                    }
                    
                    // Return the registration response
                    res.json({
                        success: true,
                        message: 'Local server registered and auto-recovery triggered',
                        serverUrl: serverUrl,
                        timestamp: new Date().toISOString()
                    });
                });
                
                return;
            }
            
            // We have registered servers, recover from all of them
            console.log(`📡 Found ${knownLocalServers.size} registered local servers`);
            
            let totalRecovered = 0;
            let totalRecords = 0;
            
            for (const [serverUrl, info] of knownLocalServers) {
                console.log(`📤 Auto-recovering from ${serverUrl}...`);
                
                try {
                    const response = await axios.post(`${serverUrl}/recovery/full`, {
                        secret: info.secret
                    }, {
                        headers: {
                            'Content-Type': 'application/json',
                            'X-Source-Secret': info.secret || process.env.REMOTE_SECRET
                        },
                        timeout: 30000
                    });
                    
                    if (response.data && response.data.success) {
                        console.log(`✅ Auto-recovered from ${serverUrl}`);
                        
                        if (response.data.result && response.data.result.recoveryResult) {
                            const recoveredCount = response.data.result.recoveryResult.recovered || 0;
                            totalRecords += recoveredCount;
                            totalRecovered++;
                            console.log(`📊 Recovered ${recoveredCount} records from ${serverUrl}`);
                        }
                    } else {
                        console.log(`⚠️ Auto-recovery from ${serverUrl} failed: ${response.data?.message || 'Unknown error'}`);
                    }
                } catch (err) {
                    console.log(`⚠️ Auto-recovery from ${serverUrl} failed: ${err.message}`);
                }
            }
            
            console.log(`✅ Auto-recovery complete: ${totalRecovered} servers, ${totalRecords} total records`);
            
            // Broadcast recovery complete
            io.emit('recovery_complete', {
                success: true,
                totalServers: totalRecovered,
                totalRecords: totalRecords,
                timestamp: new Date().toISOString()
            });
            
        } catch (err) {
            console.error('❌ Auto-recovery error:', err.message);
        }
    }, 5000); // Wait 5 seconds after startup
}

// ============================================================
// SECTION 17: START SERVER
// ============================================================

server.listen(PORT, '0.0.0.0', () => {
    const macInfo = getServerMacAddress();
    const serverIps = getServerIps();
    
    console.log(`
    ═══════════════════════════════════════════════════════
    🖥️  REMOTE SERVER - DATA RELAY & AUTHENTICATION
    ═══════════════════════════════════════════════════════
    📍 Server IP:    ${serverIps.primary}:${PORT}
    📍 Local URL:    http://localhost:${PORT}
    🔑 Server MAC:   ${macInfo.mac}
    🆔 Server ID:    ${macInfo.mac !== 'UNKNOWN' ? macInfo.mac.replace(/:/g, '').toUpperCase() : 'UNKNOWN'}
    
    📊 DATA RECOVERY:
       ✓ Auto-recovery on startup from registered local servers
       ✓ Manual recovery: POST /recover-all
       ✓ Register local server: POST /register-local-server
       ✓ Protected endpoints require whitelisted IPs
    
    🔐 PROTECTED ENDPOINTS:
       GET  /testresults    → View test results
       GET  /data           → View all data
       POST /data/realtimedata → Receive data stream
       GET  /history        → View data history
    
    🔑 WHITELIST MANAGEMENT:
       GET    /whitelist           → View whitelist
       POST   /whitelist/static    → Add static IPs
       POST   /whitelist/network   → Add network ranges
       DELETE /whitelist           → Remove from whitelist
    
    💡 To register a local server:
       POST /register-local-server { "serverUrl": "http://localhost:5000" }
    
    💡 To recover data:
       POST /recover-all
    
    ═══════════════════════════════════════════════════════
    `);
});

// ============================================================
// SECTION 18: AUTO-RECOVERY ON STARTUP
// ============================================================

// Run auto-recovery after server starts
autoRecoverOnStartup();

// ============================================================
// SECTION 19: GRACEFUL SHUTDOWN
// ============================================================

process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down gracefully...');
    
    for (const [id, socket] of connectedBranches) {
        socket.disconnect();
    }
    connectedBranches.clear();
    
    server.close(() => {
        console.log('✅ Server closed');
        process.exit(0);
    });
});

// ============================================================
// END OF REMOTE SERVER
// ============================================================