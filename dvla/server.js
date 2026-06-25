const express = require('express');
const cors = require('cors');
const http = require('http');
const socketIo = require('socket.io');
const os = require('os'); // Add this for network interfaces
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

// ============= STORAGE (in-memory, no database) =============
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

// ============= LOGGING =============
app.use((req, res, next) => {
    console.log(`\n🔵 [${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
    next();
});

// ============= TEST AUTH MIDDLEWARE (LOGS IP ONLY) =============
const authenticateBranch = (req, res, next) => {
    const branchIp = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'];
    const allowedIps = process.env.ALLOWED_BRANCH_IPS ? process.env.ALLOWED_BRANCH_IPS.split(',') : [];

    console.log(`\n🔐 BRANCH AUTH CHECK:`);
    console.log(`   📍 Client IP: ${branchIp}`);
    console.log(`   📋 Allowed IPs: ${allowedIps.length > 0 ? allowedIps.join(', ') : 'No IPs configured'}`);
    console.log(`   ✅ Auth Status: ${allowedIps.includes(branchIp) ? 'GRANTED ✅' : 'DENIED ❌'}`);
    
    // FOR TESTING: Always allow access but log everything
    if (!allowedIps.includes(branchIp)) {
        console.log(`   ⚠️  WARNING: IP ${branchIp} is NOT in the allowed list!`);
        // Uncomment below to actually block access
        // return res.status(403).json({ error: 'Unauthorized branch access' });
    }
    
    next();
};

// Apply authentication middleware to all branch endpoints
app.use('/testresults', authenticateBranch);
app.use('/data', authenticateBranch);

// ============= ROOT ENDPOINT =============
app.get('/', (req, res) => {
    // Get server's network IPs
    const networkIps = getNetworkIPs();
    
    res.json({
        name: 'Remote Data Relay Server',
        status: 'online',
        version: '1.0.0',
        description: 'Receives data from local PC and relays to branch offices',
        server_addresses: {
            localhost: `http://localhost:${PORT}`,
            network: networkIps.map(ip => `http://${ip}:${PORT}`)
        },
        endpoints: {
            receive_stream: 'POST /data/realtimedata (for local PC)',
            get_all_data: 'GET /testresults',
            get_paginated: 'GET /data/page?page=1&pageSize=100',
            search: 'POST /data/search',
            find_by_field: 'GET /data/find/:field/:value',
            stats: 'GET /data/stats',
            history: 'GET /data/history',
            health: 'GET /data/health',
            show_ip: 'GET /ipshow'
        },
        websocket: `ws://${networkIps[0] || 'localhost'}:${PORT}`,
        timestamp: new Date().toISOString()
    });
});

// Helper function to get network IPs
function getNetworkIPs() {
    const interfaces = os.networkInterfaces();
    const ips = [];
    
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            // Skip internal (localhost) and non-IPv4
            if (iface.internal || iface.family !== 'IPv4') continue;
            ips.push(iface.address);
        }
    }
    return ips;
}

// ============= IP SHOW ENDPOINT =============
app.get('/ipshow', (req, res) => {
    // Get IP from various sources (handles proxies too)
    const clientIp = req.ip || 
                    req.connection.remoteAddress || 
                    req.socket.remoteAddress || 
                    req.headers['x-forwarded-for'] || 
                    'Unknown IP';
    
    // Get all possible IP sources for debugging
    const ipSources = {
        'req.ip': req.ip || 'Not available',
        'req.connection.remoteAddress': req.connection.remoteAddress || 'Not available',
        'req.socket.remoteAddress': req.socket.remoteAddress || 'Not available',
        'req.headers.x-forwarded-for': req.headers['x-forwarded-for'] || 'Not available',
        'req.headers.true-client-ip': req.headers['true-client-ip'] || 'Not available',
        'req.headers.x-real-ip': req.headers['x-real-ip'] || 'Not available',
        'req.headers.forwarded': req.headers['forwarded'] || 'Not available'
    };
    
    // Get server's network IPs
    const serverIps = getNetworkIPs();
    
    // Clean up IP (remove port if present, handle IPv6 localhost)
    let cleanIp = clientIp;
    if (cleanIp.includes(':')) {
        // Handle IPv6 localhost
        if (cleanIp === '::1' || cleanIp === '::ffff:127.0.0.1') {
            cleanIp = '127.0.0.1';
        } else {
            // Remove port if present
            const parts = cleanIp.split(':');
            if (parts.length === 2 && !isNaN(parts[1])) {
                cleanIp = parts[0];
            }
        }
    }
    
    console.log(`\n📱 IP SHOW REQUEST:`);
    console.log(`   🌐 Client IP: ${cleanIp}`);
    console.log(`   📊 Raw IP: ${clientIp}`);
    console.log(`   🖥️  Server IPs: ${serverIps.join(', ')}`);
    console.log(`   📋 All IP Sources:`, ipSources);
    
    // Check if client is localhost or network
    const isLocalhost = cleanIp === '127.0.0.1' || cleanIp === '::1' || cleanIp === '::ffff:127.0.0.1';
    
    res.json({
        success: true,
        timestamp: new Date().toISOString(),
        your_ip: cleanIp,
        raw_ip: clientIp,
        is_localhost: isLocalhost,
        is_private_ip: isPrivateIp(cleanIp),
        server_ips: serverIps,
        access_instructions: {
            from_same_pc: `http://localhost:${PORT}/ipshow`,
            from_network: serverIps.map(ip => `http://${ip}:${PORT}/ipshow`),
            from_other_devices: `Use one of the server_ips above`
        },
        ip_sources: ipSources,
        headers: {
            'user-agent': req.headers['user-agent'] || 'Not available',
            'host': req.headers['host'] || 'Not available'
        },
        environment: process.env.NODE_ENV || 'development',
        note: isLocalhost ? "⚠️ You're accessing from the same machine (localhost). Access from another device or use your network IP to see your actual IP." : "✅ You're accessing from a network IP"
    });
});

// Helper function to check if IP is private
function isPrivateIp(ip) {
    if (!ip) return false;
    
    // Remove IPv6 prefix if present
    let cleanIp = ip.replace(/^::ffff:/, '');
    
    // Check private IP ranges
    const privateRanges = [
        /^10\./,           // 10.0.0.0/8
        /^172\.1[6-9]\./,  // 172.16.0.0/12
        /^172\.2[0-9]\./,  // 172.16.0.0/12
        /^172\.3[0-1]\./,  // 172.16.0.0/12
        /^192\.168\./,     // 192.168.0.0/16
        /^127\./,          // 127.0.0.0/8 (localhost)
        /^::1$/,           // IPv6 localhost
        /^fc00:/,          // IPv6 private
        /^fd00:/           // IPv6 private
    ];
    
    return privateRanges.some(pattern => pattern.test(cleanIp));
}

// ============= HEALTH CHECK =============
app.get('/data/health', (req, res) => {
    res.json({
        status: 'online',
        hasData: latestData.records.length > 0,
        recordCount: latestData.count,
        lastUpdate: latestData.lastUpdate,
        connectedBranches: connectedBranches.size,
        historySize: dataHistory.length,
        timestamp: new Date().toISOString()
    });
});

// ============= RECEIVE STREAM FROM LOCAL PC =============
app.post('/data/realtimedata', async (req, res) => {
    const { timestamp, records, count, source, table } = req.body;
    const sourceSecret = req.headers['x-source-secret'];
    const expectedSecret = process.env.REMOTE_SECRET;
    
    console.log(`\n📡 STREAM RECEIVED at ${new Date().toISOString()}`);
    console.log(`   Records: ${count || records?.length || 0}`);
    console.log(`   Source: ${source || 'local_pc'}`);
    console.log(`   Table: ${table || 'unknown'}`);
    
    // Verify secret if configured
    if (expectedSecret && sourceSecret !== expectedSecret) {
        console.log(`❌ Invalid secret - rejecting data`);
        return res.status(401).json({ error: 'Invalid secret' });
    }
    
    if (!records || records.length === 0) {
        console.log(`⚠️ No records in stream`);
        return res.json({ success: true, message: 'No data to process' });
    }
    
    // Store latest data
    latestData = {
        records: records,
        lastUpdate: new Date().toISOString(),
        source: source || 'local_pc',
        table: table || 'unknown',
        count: records.length,
        receivedAt: timestamp
    };
    
    // Add to history
    dataHistory.unshift({
        timestamp: new Date().toISOString(),
        recordCount: records.length,
        source: source || 'local_pc'
    });
    
    // Keep only last 50 updates
    if (dataHistory.length > MAX_HISTORY) {
        dataHistory.pop();
    }
    
    console.log(`✅ Data stored: ${records.length} records`);
    console.log(`   History size: ${dataHistory.length}`);
    
    // Broadcast to all connected branch offices via WebSocket
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

// ============= BRANCH OFFICE ENDPOINTS =============
// Get all current data
app.get('/testresults', async (req, res) => {
    console.log(`🏢 Branch requested all data`);     
    if (!latestData.records || latestData.records.length === 0) {
        return res.json({
            statusCode: 200,
            statusMessage: 'successful',
            records: [],
            message: 'No data available yet. Waiting for local PC to send data.'
        });
    }
    
    res.json({
        success: true,
        statusCode: 200,
        statusMessage: 'OK',
        records: latestData.records,
        lastUpdate: latestData.lastUpdate,
        source: latestData.source,
        table: latestData.table
    });
}); 

// Get paginated data
app.get('/data/page', async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const pageSize = Math.min(parseInt(req.query.pageSize) || 100, 1000);
    const startIndex = (page - 1) * pageSize;
    
    console.log(`🏢 Branch requested page ${page}, size ${pageSize}`);
    
    if (!latestData.records || latestData.records.length === 0) {
        return res.json({
            success: true, 
            statusCode: 200,
            statusMessage: 'OK',
            records: [],
            total: 0,
            page: page,
            pageSize: pageSize,
            totalPages: 0,
            message: 'No data available'
        });
    }
    
    const paginatedRecords = latestData.records.slice(startIndex, startIndex + pageSize);
    
    res.json({
        success: true,
        statusCode: 200,
        statusMessage: 'OK',
        records: paginatedRecords,
        total: latestData.count,
        page: page,
        pageSize: pageSize,
        totalPages: Math.ceil(latestData.count / pageSize),
        lastUpdate: latestData.lastUpdate
    });
});

// Search/filter records
app.post('/data/search', async (req, res) => {
    const { filters = {}, searchTerm = null } = req.body;
    
    console.log(`🏢 Branch search request`);
    if (searchTerm) console.log(`   Search term: ${searchTerm}`);
    if (Object.keys(filters).length > 0) console.log(`   Filters:`, filters);
    
    if (!latestData.records || latestData.records.length === 0) {
        return res.json({
            success: true,
            records: [],
            count: 0,
            message: 'No data available'
        });
    }
    
    let filteredRecords = [...latestData.records];
    
    // Global search across all fields
    if (searchTerm) {
        const term = searchTerm.toLowerCase();
        filteredRecords = filteredRecords.filter(record => {
            return Object.values(record).some(value => 
                String(value).toLowerCase().includes(term)
            );
        });
    }
    
    // Field-specific exact match filters
    if (filters && Object.keys(filters).length > 0) {
        filteredRecords = filteredRecords.filter(record => {
            return Object.entries(filters).every(([key, value]) => {
                return String(record[key]).toLowerCase() === String(value).toLowerCase();
            });
        });
    }
    
    console.log(`✅ Found ${filteredRecords.length} matching records`);
    
    res.json({
        success: true,
        records: filteredRecords,
        count: filteredRecords.length,
        total: latestData.count,
        searchTerm: searchTerm || null,
        filters: Object.keys(filters).length > 0 ? filters : null
    });
});

// Find by specific field/value
app.get('/data/find/:field/:value', async (req, res) => {
    const { field, value } = req.params;
    
    console.log(`🏢 Branch searching: ${field} = ${value}`);
    
    if (!latestData.records || latestData.records.length === 0) {
        return res.json({
            success: true,
            records: [],
            count: 0,
            message: 'No data available'
        });
    }
    
    const matchedRecords = latestData.records.filter(record => 
        String(record[field]).toUpperCase() === String(value).toUpperCase()
    );
    
    console.log(`✅ Found ${matchedRecords.length} records`);
    
    res.json({
        success: true,
        records: matchedRecords,
        count: matchedRecords.length,
        field: field,
        value: value
    });
});

// Get data statistics
app.get('/data/stats', async (req, res) => {
    console.log(`🏢 Branch requested stats`);
    
    if (!latestData.records || latestData.records.length === 0) {
        return res.json({
            success: true,
            hasData: false,
            message: 'No data available yet. Waiting for local PC to send data.'
        });
    }
    
    const columns = Object.keys(latestData.records[0] || {});
    
    // Calculate some basic stats
    const stats = {
        totalRecords: latestData.count,
        columns: columns,
        columnCount: columns.length,
        lastUpdate: latestData.lastUpdate,
        source: latestData.source,
        table: latestData.table
    };
    
    res.json({
        success: true,
        hasData: true,
        stats: stats
    });
});

// Get update history
app.get('/data/history', async (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    
    console.log(`🏢 Branch requested history (last ${limit} updates)`);
    
    res.json({
        success: true,
        history: dataHistory.slice(0, limit),
        totalUpdates: dataHistory.length,
        currentData: {
            recordCount: latestData.count,
            lastUpdate: latestData.lastUpdate
        }
    });
});

// Export all data as JSON
app.get('/data/export', async (req, res) => {
    console.log(`🏢 Branch requested data export`);
    
    if (!latestData.records || latestData.records.length === 0) {
        return res.status(404).json({
            success: false,
            message: 'No data available to export'
        });
    }
    
    res.json({
        success: true,
        exportedAt: new Date().toISOString(),
        source: latestData.source,
        table: latestData.table,
        totalRecords: latestData.count,
        data: latestData.records
    });
});

// ============= WEBSOCKET FOR BRANCH OFFICES =============
io.on('connection', (socket) => {
    const branchId = socket.id;
    const clientIp = socket.handshake.address;
    
    console.log(`\n🔐 WEBSOCKET CONNECTION:`);
    console.log(`   📍 Client IP: ${clientIp}`);
    console.log(`   🆔 Socket ID: ${branchId}`);
    
    connectedBranches.set(branchId, socket);
    
    // Send current status and data immediately
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
            message: 'Connected to data relay server - waiting for data from local PC',
            hasData: false
        });
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
        
        const filtered = latestData.records.filter(record => {
            return Object.entries(filters).every(([key, value]) => {
                return String(record[key]).toLowerCase().includes(String(value).toLowerCase());
            });
        });
        
        socket.emit('filter_response', {
            records: filtered,
            count: filtered.length,
            filters: filters,
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
                source: latestData.source
            });
        }
    });
    
    // Handle ping for connection health
    socket.on('ping', () => {
        socket.emit('pong', { timestamp: new Date().toISOString() });
    });
    
    socket.on('disconnect', () => {
        console.log(`🏢 BRANCH OFFICE DISCONNECTED: ${branchId}`);
        connectedBranches.delete(branchId);
    });
});

// ============= START SERVER =============
server.listen(PORT, '0.0.0.0', () => {  // Listen on all network interfaces
    const networkIps = getNetworkIPs();
    console.log(`
    ═══════════════════════════════════════════════════════
    🌐 REMOTE RELAY SERVER (Cloud - No Local DB)
    ═══════════════════════════════════════════════════════
    📍 Server Addresses:
    ├─ Localhost:     http://localhost:${PORT}
    ├─ Network IPs:   ${networkIps.map(ip => `http://${ip}:${PORT}`).join('\n    │               ')}
    └─ Your PC IP:    ${networkIps.find(ip => ip.startsWith('172.20.')) || networkIps[0] || 'Not found'}
    
    🔌 RECEIVE STREAM FROM LOCAL PC:
    └─ POST /data/realtimedata
    
    🏢 BRANCH OFFICE ENDPOINTS:
    ├─ GET  /testresults  - Get all current data
    ├─ GET  /data/page    - Get paginated data
    ├─ POST /data/search  - Search/filter records
    ├─ GET  /data/find/:field/:value - Find by field
    ├─ GET  /data/stats   - Get statistics
    ├─ GET  /data/history - Get update history
    ├─ GET  /data/export  - Export all data as JSON
    ├─ GET  /data/health  - Health check
    ├─ GET  /ipshow       - Show your IP address
    └─ WS   /             - WebSocket for real-time updates
    
    🔐 AUTHENTICATION TESTING:
    └─ All branch requests will log the client IP
    └─ Check .env for ALLOWED_BRANCH_IPS configuration
    
    📝 IMPORTANT: To see your actual IP (172.20.10.3), access from:
    ${networkIps.map(ip => `    http://${ip}:${PORT}/ipshow`).join('\n    ')}
    
    ⚡ Waiting for local PC to send data via POST /data/realtimedata
    ═══════════════════════════════════════════════════════
    `);
});