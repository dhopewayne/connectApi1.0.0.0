const express = require('express');
const cors = require('cors');
const http = require('http');
const socketIo = require('socket.io');
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
app.use(express.static('public'));

// ============= STORAGE FOR RECEIVED DATA =============
let latestData = {
    records: [],
    lastUpdate: null,
    source: null,
    table: null,
    count: 0
};

let dataHistory = [];
const MAX_HISTORY = 100;
let connectedBranchClients = new Map();

// ============= LOGGING MIDDLEWARE =============
app.use((req, res, next) => {
    console.log(`\n🔵 [${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
    if (Object.keys(req.query).length > 0) {
        console.log(`   Query:`, req.query);
    }
    if (req.body && Object.keys(req.body).length > 0) {
        const safeBody = { ...req.body };
        if (safeBody.records) safeBody.records = `${safeBody.records.length} records`;
        console.log(`   Body:`, safeBody);
    }
    next();
});

// ============= REAL-TIME DATA ENDPOINT (Receives from local server) =============
app.post('/realtimedata', async (req, res) => {
    const { timestamp, records, count, source, table } = req.body;
    const sourceSecret = req.headers['x-source-secret'];
    const expectedSecret = process.env.REMOTE_SECRET;
    
    console.log(`\n📡 REAL-TIME DATA RECEIVED at ${new Date().toISOString()}`);
    console.log(`   Source: ${source || 'local_server'}`);
    console.log(`   Table: ${table || 'unknown'}`);
    console.log(`   Records: ${count || records?.length || 0}`);
    console.log(`   Timestamp: ${timestamp}`);
    
    // Verify secret if configured
    if (expectedSecret && sourceSecret !== expectedSecret) {
        console.log(`❌ Invalid secret received`);
        return res.status(401).json({ error: 'Invalid secret' });
    }
    
    if (!records || records.length === 0) {
        console.log(`⚠️ No records received`);
        return res.json({ success: true, message: 'No data to process' });
    }
    
    // Store the latest data
    latestData = {
        records: records,
        lastUpdate: new Date().toISOString(),
        source: source || 'local_server',
        table: table || 'unknown',
        count: records.length,
        receivedAt: timestamp
    };
    
    // Add to history
    dataHistory.unshift({
        ...latestData,
        id: Date.now()
    });
    
    // Keep only last MAX_HISTORY entries
    if (dataHistory.length > MAX_HISTORY) {
        dataHistory.pop();
    }
    
    console.log(`✅ Data stored: ${records.length} records`);
    console.log(`   Current history size: ${dataHistory.length}`);
    
    // Broadcast to all connected branch clients via WebSocket
    const broadcastPayload = {
        type: 'live_update',
        timestamp: new Date().toISOString(),
        records: records,
        count: records.length,
        source: source,
        table: table
    };
    
    let clientsNotified = 0;
    for (const [clientId, clientSocket] of connectedBranchClients) {
        clientSocket.emit('data_update', broadcastPayload);
        clientsNotified++;
    }
    
    console.log(`📢 Broadcast to ${clientsNotified} connected branch clients`);
    
    res.json({ 
        success: true, 
        received: records.length,
        stored: true,
        clientsNotified,
        timestamp: new Date().toISOString()
    });
});

// ============= ENDPOINTS FOR BRANCH OFFICES =============

// Get all current data (full dataset)
app.get('/api/data/all', async (req, res) => {
    console.log(`🎯 [BRANCH] GET /api/data/all`);
    
    if (!latestData.records || latestData.records.length === 0) {
        return res.status(404).json({ 
            success: false, 
            message: 'No data available yet. Waiting for local server to send data.',
            records: [],
            count: 0
        });
    }
    
    res.json({
        success: true,
        records: latestData.records,
        count: latestData.count,
        lastUpdate: latestData.lastUpdate,
        source: latestData.source,
        table: latestData.table
    });
});

// Get paginated data
app.get('/api/data/page', async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const pageSize = Math.min(parseInt(req.query.pageSize) || 100, 1000);
    const startIndex = (page - 1) * pageSize;
    const endIndex = startIndex + pageSize;
    
    console.log(`🎯 [BRANCH] GET /api/data/page - Page ${page}, Size ${pageSize}`);
    
    if (!latestData.records || latestData.records.length === 0) {
        return res.json({
            success: true,
            records: [],
            total: 0,
            page,
            pageSize,
            totalPages: 0,
            message: 'No data available yet'
        });
    }
    
    const paginatedRecords = latestData.records.slice(startIndex, endIndex);
    
    res.json({
        success: true,
        records: paginatedRecords,
        total: latestData.count,
        page,
        pageSize,
        totalPages: Math.ceil(latestData.count / pageSize),
        lastUpdate: latestData.lastUpdate
    });
});

// Search/filter records
app.post('/api/data/search', async (req, res) => {
    const { filters = {}, searchTerm = null } = req.body;
    
    console.log(`🎯 [BRANCH] POST /api/data/search`);
    console.log(`   Filters:`, filters);
    if (searchTerm) console.log(`   Search term: ${searchTerm}`);
    
    if (!latestData.records || latestData.records.length === 0) {
        return res.json({
            success: true,
            records: [],
            count: 0,
            message: 'No data available'
        });
    }
    
    let filteredRecords = [...latestData.records];
    
    // Apply search term across all fields
    if (searchTerm) {
        const term = searchTerm.toLowerCase();
        filteredRecords = filteredRecords.filter(record => {
            return Object.values(record).some(value => 
                String(value).toLowerCase().includes(term)
            );
        });
    }
    
    // Apply specific field filters
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
        filters: filters,
        searchTerm: searchTerm || null,
        lastUpdate: latestData.lastUpdate
    });
});

// Get data history (last N updates)
app.get('/api/data/history', async (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    
    console.log(`🎯 [BRANCH] GET /api/data/history - Limit: ${limit}`);
    
    res.json({
        success: true,
        history: dataHistory.slice(0, limit),
        totalHistory: dataHistory.length,
        currentData: {
            records: latestData.count,
            lastUpdate: latestData.lastUpdate
        }
    });
});

// Get data summary/stats
app.get('/api/data/summary', async (req, res) => {
    console.log(`🎯 [BRANCH] GET /api/data/summary`);
    
    if (!latestData.records || latestData.records.length === 0) {
        return res.json({
            success: true,
            hasData: false,
            message: 'No data available yet'
        });
    }
    
    // Get column names from first record
    const columns = Object.keys(latestData.records[0] || {});
    
    // Get unique values for each column (sample)
    const sampleValues = {};
    columns.forEach(col => {
        const uniqueValues = new Set();
        latestData.records.slice(0, 100).forEach(record => {
            if (record[col]) uniqueValues.add(String(record[col]));
        });
        sampleValues[col] = Array.from(uniqueValues).slice(0, 10);
    });
    
    res.json({
        success: true,
        hasData: true,
        stats: {
            totalRecords: latestData.count,
            columns: columns,
            columnCount: columns.length,
            lastUpdate: latestData.lastUpdate,
            source: latestData.source,
            table: latestData.table
        },
        sampleValues: sampleValues,
        firstRecord: latestData.records[0],
        lastRecord: latestData.records[latestData.records.length - 1]
    });
});

// Export data as JSON
app.get('/api/data/export', async (req, res) => {
    console.log(`🎯 [BRANCH] GET /api/data/export`);
    
    if (!latestData.records || latestData.records.length === 0) {
        return res.status(404).json({ error: 'No data available' });
    }
    
    const format = req.query.format || 'json';
    
    if (format === 'json') {
        res.json({
            exportedAt: new Date().toISOString(),
            source: latestData.source,
            table: latestData.table,
            totalRecords: latestData.count,
            data: latestData.records
        });
    } else {
        res.status(400).json({ error: 'Format not supported. Use format=json' });
    }
});

// Health check
app.get('/api/health', async (req, res) => {
    res.json({
        status: 'online',
        hasData: latestData.records.length > 0,
        recordCount: latestData.count,
        lastUpdate: latestData.lastUpdate,
        connectedClients: connectedBranchClients.size,
        historySize: dataHistory.length,
        timestamp: new Date().toISOString()
    });
});

// Get server info
app.get('/api/info', async (req, res) => {
    res.json({
        name: 'Remote Data Proxy Server',
        version: '1.0.0',
        endpoints: [
            'POST /realtimedata - Receive data from local server',
            'GET /api/data/all - Get all current data',
            'GET /api/data/page - Get paginated data',
            'POST /api/data/search - Search/filter records',
            'GET /api/data/history - Get update history',
            'GET /api/data/summary - Get data summary',
            'GET /api/data/export - Export data as JSON',
            'GET /api/health - Health check',
            'GET /api/stats - Real-time statistics',
            'WS / - WebSocket for real-time updates'
        ],
        config: {
            maxHistory: MAX_HISTORY,
            requiresAuth: !!process.env.REMOTE_SECRET
        }
    });
});

// Real-time statistics endpoint
app.get('/api/stats', async (req, res) => {
    const stats = {
        currentData: {
            recordCount: latestData.count,
            lastUpdate: latestData.lastUpdate,
            source: latestData.source,
            table: latestData.table
        },
        connectionStats: {
            activeBranchClients: connectedBranchClients.size,
            totalUpdatesReceived: dataHistory.length
        },
        serverTime: new Date().toISOString(),
        uptime: process.uptime()
    };
    
    // Calculate update frequency
    if (dataHistory.length >= 2) {
        const lastTwo = dataHistory.slice(0, 2);
        const timeDiff = new Date(lastTwo[0].lastUpdate) - new Date(lastTwo[1].lastUpdate);
        stats.updateFrequency = `${Math.round(timeDiff / 1000)} seconds between updates`;
    }
    
    res.json(stats);
});

// ============= WEBSOCKET FOR BRANCH CLIENTS =============
io.on('connection', (socket) => {
    const clientId = socket.id;
    const clientIp = socket.handshake.address;
    
    console.log(`🏢 BRANCH CLIENT CONNECTED: ${clientId} from ${clientIp}`);
    connectedBranchClients.set(clientId, socket);
    
    // Send current data immediately on connection
    if (latestData.records && latestData.records.length > 0) {
        socket.emit('connected', {
            message: 'Connected to remote data proxy',
            currentData: {
                count: latestData.count,
                lastUpdate: latestData.lastUpdate,
                hasData: true
            }
        });
        
        // Send the latest data
        socket.emit('data_update', {
            type: 'initial',
            timestamp: new Date().toISOString(),
            records: latestData.records,
            count: latestData.count,
            source: latestData.source,
            table: latestData.table
        });
        
        console.log(`📤 Sent initial data (${latestData.count} records) to ${clientId}`);
    } else {
        socket.emit('connected', {
            message: 'Connected to remote data proxy - waiting for data from local server',
            currentData: {
                hasData: false
            }
        });
    }
    
    // Handle subscription to specific filters
    socket.on('subscribe', (filters = {}) => {
        console.log(`📺 Client ${clientId} subscribed with filters:`, filters);
        socket.filters = filters;
        socket.emit('subscribed', { filters, timestamp: new Date().toISOString() });
    });
    
    // Handle request for filtered data
    socket.on('request_filtered', async (filters) => {
        console.log(`🔍 Client ${clientId} requesting filtered data:`, filters);
        
        if (!latestData.records) {
            socket.emit('filtered_data', { records: [], count: 0 });
            return;
        }
        
        const filtered = latestData.records.filter(record => {
            return Object.entries(filters).every(([key, value]) => {
                return String(record[key]).toLowerCase().includes(String(value).toLowerCase());
            });
        });
        
        socket.emit('filtered_data', {
            records: filtered,
            count: filtered.length,
            filters,
            timestamp: new Date().toISOString()
        });
    });
    
    // Handle ping/pong for connection health
    socket.on('ping', () => {
        socket.emit('pong', { timestamp: new Date().toISOString() });
    });
    
    socket.on('disconnect', () => {
        console.log(`🏢 BRANCH CLIENT DISCONNECTED: ${clientId}`);
        connectedBranchClients.delete(clientId);
    });
});

// ============= DASHBOARD =============
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/remote-dashboard.html');
});

app.get('/dashboard', (req, res) => {
    res.sendFile(__dirname + '/public/remote-dashboard.html');
});

// ============= START SERVER =============
server.listen(PORT, () => {
    console.log(`
    ═══════════════════════════════════════════════════════
    🌐 REMOTE PROXY SERVER (Receiver)
    ═══════════════════════════════════════════════════════
    📍 URL:              http://localhost:${PORT}
    🔗 Public URL:       ${process.env.PUBLIC_URL || `http://localhost:${PORT}`}
    
    📡 Endpoints for Local Server:
    └─ POST /realtimedata - Receive real-time data
    
    🏢 Endpoints for Branch Offices:
    ├─ GET  /api/data/all     - Get all current data
    ├─ GET  /api/data/page    - Get paginated data
    ├─ POST /api/data/search  - Search/filter records
    ├─ GET  /api/data/history - Get update history
    ├─ GET  /api/data/summary - Get data summary
    ├─ GET  /api/health       - Health check
    └─ WS   /                 - WebSocket for real-time updates
    
    📊 Current Status:
    ├─ Waiting for local server to send data...
    └─ Ready to accept branch connections
    ═══════════════════════════════════════════════════════
    `);
});