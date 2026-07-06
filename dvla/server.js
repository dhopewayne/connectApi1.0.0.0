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

// Track ALL PCs accessing the server (historical data)
let pcAccessLog = new Map(); // Key: client_ip, Value: PC info

// Track currently active PCs (real-time connections)
let activePCs = new Map(); // Key: client_ip, Value: { connectionInfo, lastSeen, socketIds }

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
 * This gets the IP of whoever is CONNECTING to this server
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
 * Get server's own IP addresses
 * This gets the IP of THIS SERVER (not the client)
 */
function getServerIps() {
    const interfaces = os.networkInterfaces();
    const ips = {
        ipv4: [],
        ipv6: []
    };
    
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            // Skip internal (loopback) addresses
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
    
    // Also get localhost
    ips.localhost = '127.0.0.1';
    
    // Get primary IP (first non-internal IPv4)
    ips.primary = ips.ipv4.length > 0 ? ips.ipv4[0].address : '127.0.0.1';
    
    return ips;
}

/**
 * Get server's unique MAC address (hardware address)
 * This never changes for the server
 */
function getServerMacAddress() {
    const interfaces = os.networkInterfaces();
    
    // First try to get MAC from a non-internal interface
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            // Skip internal (loopback) addresses
            if (iface.internal) continue;
            // Skip if no MAC address
            if (!iface.mac || iface.mac === '00:00:00:00:00:00') continue;
            
            return {
                mac: iface.mac,
                interface: name,
                family: iface.family,
                address: iface.address
            };
        }
    }
    
    // If no non-internal interface found, get from any interface
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
    
    // Fallback
    return {
        mac: 'UNKNOWN',
        interface: 'unknown',
        family: 'unknown',
        address: 'unknown'
    };
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
    const serverIps = getServerIps();
    
    return {
        // The client who is connecting
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
        // The server they are connecting to
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

/**
 * Middleware to track all PCs/servers accessing this server
 */
app.use((req, res, next) => {
    const networkInfo = getClientNetworkInfo(req);
    const clientIp = networkInfo.client.ip;
    const isWhitelisted = networkInfo.client.is_whitelisted;
    const isLocal = networkInfo.connection_type === 'LOCAL';
    
    // Store in request for later use
    req.clientInfo = networkInfo.client;
    req.serverInfo = networkInfo.server;
    req.connectionType = networkInfo.connection_type;
    
    if (clientIp && clientIp !== 'Unknown' && clientIp !== '127.0.0.1') {
        // Update historical log
        if (!pcAccessLog.has(clientIp)) {
            // New PC/Server detected
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
            console.log(`🆕 NEW ${isLocal ? 'LOCAL' : 'REMOTE'} CLIENT DETECTED: ${clientIp} (Whitelisted: ${isWhitelisted})`);
        }
        
        // Update existing PC record
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
        
        // Update active PCs
        if (!activePCs.has(clientIp)) {
            // New active connection
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
            console.log(`✅ ${isLocal ? 'LOCAL' : 'REMOTE'} CLIENT CONNECTED: ${clientIp} (Active sessions: ${activePCs.size})`);
            
            // Broadcast active PCs update
            broadcastActivePCs();
        } else {
            // Update existing active connection
            const activeRecord = activePCs.get(clientIp);
            activeRecord.last_seen = new Date().toISOString();
            activeRecord.requests_in_session += 1;
            activeRecord.ip_chain = networkInfo.client.ip_chain;
            activeRecord.user_agent = networkInfo.client.user_agent;
            activeRecord.is_whitelisted = isWhitelisted;
            activeRecord.is_local = isLocal;
            activeRecord.connection_type = networkInfo.connection_type;
            activeRecord.server_info = networkInfo.server;
            
            // Add socket ID if not present
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

/**
 * Middleware to authenticate and check whitelist
 * Returns 403 if IP is not whitelisted
 */
const authenticateBranch = async (req, res, next) => {
    const clientIp = req.clientInfo?.ip || 'Unknown';
    const isWhitelisted = req.clientInfo?.is_whitelisted || false;
    
    // Check if whitelisted
    if (!isWhitelisted) {
        console.log(`❌ ENDPOINT ACCESS DENIED for ${clientIp}`);
        
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
            message: `Contact network administrator for clarification.`,
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
 */
app.post('/whitelist/static', (req, res) => {
    let ipsToAdd = [];
    
    if (req.body.ipData && Array.isArray(req.body.ipData)) {
        ipsToAdd = req.body.ipData
            .map(item => item.ipAddress || item.ip)
            .filter(Boolean);
        console.log(`📥 Received IP data from local server: ${ipsToAdd.length} IPs`);
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
            // Update PC record if exists
            if (pcAccessLog.has(ip)) {
                const record = pcAccessLog.get(ip);
                record.is_whitelisted = true;
                pcAccessLog.set(ip, record);
            }
            // Update active PC record
            if (activePCs.has(ip)) {
                const activeRecord = activePCs.get(ip);
                activeRecord.is_whitelisted = true;
                activePCs.set(ip, activeRecord);
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

/**
 * Add network ranges to whitelist
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
            // Update active PCs
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

/**
 * Remove from whitelist
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
// SECTION 10: PC TRACKING ENDPOINTS
// ============================================================

/**
 * Show ALL clients that have EVER accessed this server (historical)
 */
app.get('/all-pcs-history', (req, res) => {
    const allPCs = [];
    let whitelistedCount = 0;
    let totalRequests = 0;
    let deniedCount = 0;
    let localCount = 0;
    let remoteCount = 0;
    
    for (const [ip, info] of pcAccessLog) {
        allPCs.push({
            ip: ip,
            ...info
        });
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
        whitelist: {
            static_ips: whitelistedStaticIps,
            networks: whitelistedNetworks
        },
        timestamp: new Date().toISOString()
    });
});

/**
 * Show CURRENTLY ACTIVE clients (real-time)
 */
app.get('/all-pcs', (req, res) => {
    const activePCsList = [];
    let whitelistedCount = 0;
    let localCount = 0;
    let remoteCount = 0;
    
    for (const [ip, info] of activePCs) {
        activePCsList.push({
            ip: ip,
            ...info
        });
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
        whitelist: {
            static_ips: whitelistedStaticIps,
            networks: whitelistedNetworks
        },
        server_info: {
            primary_ip: getServerIps().primary,
            port: PORT,
            hostname: os.hostname()
        },
        timestamp: new Date().toISOString()
    });
});

/**
 * Show details for a specific client
 */
app.get('/pc/:ip', (req, res) => {
    const ip = req.params.ip;
    
    if (!pcAccessLog.has(ip)) {
        return res.status(404).json({
            success: false,
            error: 'Client not found',
            message: `No client with IP ${ip} has accessed this server`
        });
    }
    
    const pcInfo = pcAccessLog.get(ip);
    const isActive = activePCs.has(ip);
    const activeInfo = isActive ? activePCs.get(ip) : null;
    
    res.json({
        success: true,
        client: {
            ip: ip,
            ...pcInfo,
            currently_active: isActive,
            active_session: activeInfo ? {
                connected_at: activeInfo.connected_at,
                last_seen: activeInfo.last_seen,
                requests_in_session: activeInfo.requests_in_session,
                socket_ids: activeInfo.socket_ids,
                server_connected_to: activeInfo.server_info
            } : null
        },
        timestamp: new Date().toISOString()
    });
});

/**
 * Clear PC access log (historical only)
 */
app.delete('/all-pcs-history', (req, res) => {
    const count = pcAccessLog.size;
    pcAccessLog.clear();
    
    console.log(`🗑️ Client history cleared (${count} clients removed from history)`);
    
    res.json({
        success: true,
        message: `Cleared client history (${count} clients)`,
        removed_count: count,
        active_clients_remain: activePCs.size,
        timestamp: new Date().toISOString()
    });
});

/**
 * Remove a specific client from active list (force disconnect)
 */
app.delete('/pc/:ip/disconnect', (req, res) => {
    const ip = req.params.ip;
    
    if (!activePCs.has(ip)) {
        return res.status(404).json({
            success: false,
            error: 'Client not active',
            message: `No active client with IP ${ip}`
        });
    }
    
    const activeInfo = activePCs.get(ip);
    activePCs.delete(ip);
    
    console.log(`🔌 CLIENT DISCONNECTED (forced): ${ip} (${activeInfo.is_local ? 'LOCAL' : 'REMOTE'})`);
    
    broadcastActivePCs();
    
    res.json({
        success: true,
        message: `Client ${ip} disconnected`,
        client_type: activeInfo.is_local ? 'LOCAL' : 'REMOTE',
        disconnected_at: new Date().toISOString(),
        timestamp: new Date().toISOString()
    });
});

/**
 * Check your own client info and connection status
 */
app.get('/my-pc-check', (req, res) => {
    const clientInfo = req.clientInfo;
    const serverInfo = req.serverInfo;
    const connectionType = req.connectionType;
    const clientIp = clientInfo?.ip || 'Unknown';
    const isWhitelisted = clientInfo?.is_whitelisted || false;
    const isActive = activePCs.has(clientIp);
    
    console.log(`\n🖥️ CLIENT CHECK from ${clientIp} (${connectionType})`);
    
    const pcHistory = pcAccessLog.get(clientIp);
    const activeInfo = activePCs.get(clientIp);
    
    res.json({
        success: true,
        your_info: {
            client_ip: clientIp,
            connection_type: connectionType,
            is_local: connectionType === 'LOCAL',
            is_whitelisted: isWhitelisted,
            is_active: isActive,
            active_since: activeInfo?.connected_at || null,
            last_seen: activeInfo?.last_seen || null,
            total_requests: pcHistory?.total_requests || 0,
            first_seen: pcHistory?.first_seen || null,
            denied_count: pcHistory?.denied_count || 0,
            user_agent: clientInfo?.user_agent || 'Unknown'
        },
        server_you_are_connecting_to: {
            primary_ip: serverInfo?.primary_ip || 'Unknown',
            port: serverInfo?.port || PORT,
            hostname: serverInfo?.hostname || os.hostname(),
            all_ips: serverInfo?.all_ipv4 || []
        },
        whitelist_status: {
            status: isWhitelisted ? '✅ AUTHORIZED' : '❌ NOT AUTHORIZED',
            message: isWhitelisted 
                ? `Your client (${clientIp}) is authorized to access protected endpoints`
                : `Your client (${clientIp || 'unknown'}) is NOT authorized to access protected endpoints`
        },
        server_whitelist: {
            static_ips: whitelistedStaticIps,
            networks: whitelistedNetworks
        },
        timestamp: new Date().toISOString()
    });
});

/**
 * Get your server's unique MAC address
 */
app.get('/server-mac', (req, res) => {
    const macInfo = getServerMacAddress();
    const serverIps = getServerIps();
    
    console.log(`\n🔑 SERVER MAC QUERY from ${req.clientInfo?.ip || 'unknown'}`);
    console.log(`   MAC Address: ${macInfo.mac}`);
    console.log(`   Interface: ${macInfo.interface}`);
    
    const serverId = macInfo.mac !== 'UNKNOWN' 
        ? macInfo.mac.replace(/:/g, '').toUpperCase()
        : 'UNKNOWN_SERVER';
    
    res.json({
        success: true,
        server: {
            name: os.hostname(),
            platform: os.platform(),
            type: os.type(),
            release: os.release()
        },
        unique_identifier: {
            mac_address: macInfo.mac,
            server_id: serverId,
            interface: macInfo.interface,
            is_permanent: true,
            note: "MAC address is hardware-based and never changes"
        },
        network: {
            primary_ip: serverIps.primary,
            all_ipv4: serverIps.ipv4.map(ip => ({
                interface: ip.interface,
                address: ip.address,
                mac: ip.mac
            }))
        },
        timestamp: new Date().toISOString()
    });
});

/**
 * Get your own server IP address (the IP you're connecting from)
 */
app.get('/my-ip', (req, res) => {
    const clientInfo = req.clientInfo;
    const serverInfo = req.serverInfo;
    const connectionType = req.connectionType;
    const clientIp = clientInfo?.ip || 'Unknown';
    
    const allIps = {
        detected_ip: clientIp,
        x_forwarded_for: req.headers['x-forwarded-for'] || null,
        x_real_ip: req.headers['x-real-ip'] || null,
        cf_connecting_ip: req.headers['cf-connecting-ip'] || null,
        remote_address: req.socket?.remoteAddress || null,
        socket_local_address: req.socket?.localAddress || null
    };
    
    console.log(`\n🌐 IP QUERY from ${clientIp} (${connectionType})`);
    
    res.json({
        success: true,
        message: "Your client IP address",
        your_client_ip: clientIp,
        connection_type: connectionType,
        is_local: connectionType === 'LOCAL',
        all_detected_ips: allIps,
        server_info: {
            primary_ip: serverInfo?.primary_ip || 'Unknown',
            port: serverInfo?.port || PORT,
            hostname: serverInfo?.hostname || os.hostname()
        },
        timestamp: new Date().toISOString()
    });
});

// ============================================================
// SECTION 11: PROTECTED ENDPOINTS
// ============================================================

/**
 * TEST RESULTS endpoint - Protected by whitelist
 */
app.get('/testresults', authenticateBranch, (req, res) => {
    console.log(`📊 TEST RESULTS requested by ${req.clientInfo?.ip}`);
    
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
 */
app.get('/data', authenticateBranch, (req, res) => {
    res.json({
        success: true,
        message: 'Protected data endpoint',
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
    console.log(`   From IP: ${req.clientInfo?.ip}`);
    console.log(`   Connection: ${req.connectionType}`);
    console.log(`   Records: ${count || (records && records.length) || 0}`);

    if (expectedSecret && sourceSecret !== expectedSecret) {
        console.log(`❌ Invalid secret — rejecting data`);
        return res.status(401).json({
            success: false,
            error: 'Invalid secret',
            your_ip: req.clientInfo?.ip
        });
    }

    if (!records || records.length === 0) {
        console.log(`⚠️ No records in stream`);
        return res.json({ 
            success: true, 
            message: 'No data to process',
            your_ip: req.clientInfo?.ip
        });
    }

    latestData = {
        records: records,
        lastUpdate: new Date().toISOString(),
        receivedAt: timestamp || new Date().toISOString()
    };

    dataHistory.unshift({
        timestamp: new Date().toISOString(),
        recordCount: records.length,
        source: source || 'local_pc',
        from_ip: req.clientInfo?.ip,
        connection_type: req.connectionType
    });

    if (dataHistory.length > MAX_HISTORY) dataHistory.pop();

    const broadcastPayload = {
        type: 'live_update',
        timestamp: new Date().toISOString(),
        records: records
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

// ============================================================
// SECTION 12: DATA HISTORY ENDPOINT
// ============================================================

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
// SECTION 13: BROADCAST FUNCTIONS
// ============================================================

function broadcastActivePCs() {
    const activePCsList = [];
    for (const [ip, info] of activePCs) {
        activePCsList.push({
            ip: ip,
            ...info
        });
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
        name: 'PC/Server Tracking & Authentication System',
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
            local_active: [...activePCs.values()].filter(c => c.is_local).length,
            remote_active: [...activePCs.values()].filter(c => !c.is_local).length,
            data_records: latestData.records?.length || 0
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
    const clientMac = socket.handshake.headers['x-mac-address'] || 'Not provided';
    const isLocal = clientIp === '127.0.0.1' || clientIp === '::1';
    
    const isWhitelisted = isIpWhitelisted(clientIp);

    console.log(`\n🔐 WEBSOCKET CONNECTION:`);
    console.log(`   📍 Client IP: ${clientIp}`);
    console.log(`   🖥️  MAC:       ${clientMac}`);
    console.log(`   🆔 Socket ID: ${branchId}`);
    console.log(`   🔑 Whitelisted: ${isWhitelisted}`);
    console.log(`   📍 Type: ${isLocal ? 'LOCAL' : 'REMOTE'}`);

    connectedBranches.set(branchId, socket);

    socket.emit('connected', {
        status: 'connected',
        message: 'Connected to data relay server',
        client_ip: clientIp,
        is_whitelisted: isWhitelisted,
        is_local: isLocal,
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

    // Send initial active clients list
    const initialActiveClients = [];
    for (const [ip, info] of activePCs) {
        initialActiveClients.push({
            ip: ip,
            ...info
        });
    }
    socket.emit('active_clients_update', {
        type: 'initial',
        timestamp: new Date().toISOString(),
        active_clients: initialActiveClients,
        count: initialActiveClients.length
    });

    if (latestData.records && latestData.records.length > 0) {
        socket.emit('data_update', {
            type: 'initial',
            timestamp: new Date().toISOString(),
            records: latestData.records,
            count: latestData.count
        });
        console.log(`📤 Sent initial data (${latestData.count} records) to client ${branchId}`);
    }

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
                count: latestData.count
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
                console.log(`🔌 CLIENT DISCONNECTED: ${ip} (${info.is_local ? 'LOCAL' : 'REMOTE'})`);
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
// SECTION 16: GRACEFUL SHUTDOWN
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
// SECTION 17: START SERVER
// ============================================================

server.listen(PORT, '0.0.0.0', () => {
    const macInfo = getServerMacAddress();
    const serverIps = getServerIps();
    
    console.log(`
    ═══════════════════════════════════════════════════════
    🖥️  SERVER TRACKING & AUTHENTICATION SYSTEM (REAL-TIME)
    ═══════════════════════════════════════════════════════
    📍 Server IP:    ${serverIps.primary}:${PORT}
    📍 Local URL:    http://localhost:${PORT}
    🔑 Server MAC:   ${macInfo.mac} (${macInfo.interface})
    🆔 Server ID:    ${macInfo.mac !== 'UNKNOWN' ? macInfo.mac.replace(/:/g, '').toUpperCase() : 'UNKNOWN'}
    
    📊 TRACKING:
       GET  /all-pcs           → Currently active clients (real-time)
       GET  /all-pcs-history   → All clients that ever connected
       GET  /pc/:ip            → Details for a specific client
    
    🔐 AUTHENTICATION:
       GET  /my-ip        → Your client IP address
       GET  /my-pc-check  → Your connection status
       GET  /server-mac   → Server's unique MAC address
    
    🔑 WHITELIST MANAGEMENT:
       GET    /whitelist           → View whitelist
       POST   /whitelist/static    → Add static IPs
       POST   /whitelist/network   → Add network ranges
       DELETE /whitelist           → Remove from whitelist
    
    💡 Test from any client:
       curl http://${serverIps.primary}:${PORT}/my-ip
       curl http://${serverIps.primary}:${PORT}/all-pcs
    
    ═══════════════════════════════════════════════════════
    `);
});

// ============================================================
// END OF SERVER
// ============================================================