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

// ============= STORAGE =============
let latestData = {
    records: [],
    lastUpdate: null,
    source: null,
    table: null,
    count: 0
};

let connectedBranches = new Map(); // Track connected branch offices

// ============= LOGGING =============
app.use((req, res, next) => {
    console.log(`\n🔵 [${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
    next();
});

// ============= RECEIVE STREAM FROM LOCAL SERVER =============
app.post('/realtimedata', async (req, res) => {
    const { timestamp, records, count, source, table } = req.body;
    const sourceSecret = req.headers['x-source-secret'];
    const expectedSecret = process.env.REMOTE_SECRET;
    
    console.log(`\n📡 STREAM RECEIVED at ${new Date().toISOString()}`);
    console.log(`   Records: ${count || records?.length || 0}`);
    console.log(`   Source: ${source || 'local_server'}`);
    
    // Verify secret
    if (expectedSecret && sourceSecret !== expectedSecret) {
        console.log(`❌ Invalid secret`);
        return res.status(401).json({ error: 'Invalid secret' });
    }
    
    if (!records || records.length === 0) {
        return res.json({ success: true, message: 'No data' });
    }
    
    // Store latest data
    latestData = {
        records: records,
        lastUpdate: new Date().toISOString(),
        source: source || 'local_server',
        table: table || 'unknown',
        count: records.length,
        receivedAt: timestamp
    };
    
    console.log(`✅ Data stored: ${records.length} records`);
    
    // Broadcast to all connected branch offices
    const broadcastPayload = {
        type: 'live_update',
        timestamp: new Date().toISOString(),
        records: records,
        count: records.length
    };
    
    let branchesNotified = 0;
    for (const [branchId, branchSocket] of connectedBranches) {
        branchSocket.emit('data_update', broadcastPayload);
        branchesNotified++;
    }
    
    console.log(`📢 Broadcast to ${branchesNotified} branch offices`);
    
    res.json({ 
        success: true, 
        received: records.length,
        branchesNotified
    });
});

// ============= ENDPOINTS FOR BRANCH OFFICES =============

// Get all current data
app.get('/api/data/all', async (req, res) => {
    console.log(`🏢 Branch requested all data`);
    
    if (!latestData.records || latestData.records.length === 0) {
        return res.json({
            success: true,
            records: [],
            count: 0,
            message: 'No data available yet'
        });
    }
    
    res.json({
        success: true,
        records: latestData.records,
        count: latestData.count,
        lastUpdate: latestData.lastUpdate
    });
});

// Get paginated data
app.get('/api/data/page', async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const pageSize = Math.min(parseInt(req.query.pageSize) || 100, 1000);
    const startIndex = (page - 1) * pageSize;
    
    console.log(`🏢 Branch requested page ${page}, size ${pageSize}`);
    
    if (!latestData.records || latestData.records.length === 0) {
        return res.json({
            success: true,
            records: [],
            total: 0,
            page,
            pageSize,
            totalPages: 0
        });
    }
    
    const paginatedRecords = latestData.records.slice(startIndex, startIndex + pageSize);
    
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
    
    console.log(`🏢 Branch search request - Filters:`, filters);
    
    if (!latestData.records || latestData.records.length === 0) {
        return res.json({
            success: true,
            records: [],
            count: 0
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
    
    // Field-specific filters
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
        total: latestData.count
    });
});

// Get single record by any field value
app.get('/api/data/find/:field/:value', async (req, res) => {
    const { field, value } = req.params;
    
    console.log(`🏢 Branch searching: ${field} = ${value}`);
    
    if (!latestData.records || latestData.records.length === 0) {
        return res.json({
            success: true,
            records: [],
            count: 0
        });
    }
    
    const matchedRecords = latestData.records.filter(record => 
        String(record[field]).toLowerCase() === String(value).toLowerCase()
    );
    
    res.json({
        success: true,
        records: matchedRecords,
        count: matchedRecords.length,
        field,
        value
    });
});

// Get data summary/stats
app.get('/api/data/stats', async (req, res) => {
    console.log(`🏢 Branch requested stats`);
    
    if (!latestData.records || latestData.records.length === 0) {
        return res.json({
            success: true,
            hasData: false,
            message: 'No data available'
        });
    }
    
    const columns = Object.keys(latestData.records[0] || {});
    
    res.json({
        success: true,
        hasData: true,
        totalRecords: latestData.count,
        columns: columns,
        columnCount: columns.length,
        lastUpdate: latestData.lastUpdate,
        source: latestData.source
    });
});

// Health check for branches
app.get('/api/health', async (req, res) => {
    res.json({
        status: 'online',
        hasData: latestData.records.length > 0,
        recordCount: latestData.count,
        lastUpdate: latestData.lastUpdate,
        connectedBranches: connectedBranches.size,
        timestamp: new Date().toISOString()
    });
});

// ============= WEBSOCKET FOR BRANCH OFFICES =============
io.on('connection', (socket) => {
    const branchId = socket.id;
    console.log(`🏢 BRANCH OFFICE CONNECTED: ${branchId}`);
    connectedBranches.set(branchId, socket);
    
    // Send current data immediately
    if (latestData.records && latestData.records.length > 0) {
        socket.emit('connected', {
            status: 'connected',
            recordCount: latestData.count,
            lastUpdate: latestData.lastUpdate
        });
        
        socket.emit('data_update', {
            type: 'initial',
            timestamp: new Date().toISOString(),
            records: latestData.records,
            count: latestData.count
        });
        
        console.log(`📤 Sent initial data (${latestData.count} records) to branch ${branchId}`);
    } else {
        socket.emit('connected', {
            status: 'connected',
            message: 'Waiting for data from local server'
        });
    }
    
    // Branch can request filtered data
    socket.on('filter_request', (filters) => {
        console.log(`🔍 Branch ${branchId} requested filter:`, filters);
        
        if (!latestData.records) {
            socket.emit('filter_response', { records: [], count: 0 });
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
            filters
        });
    });
    
    // Branch can request refresh
    socket.on('refresh_request', () => {
        if (latestData.records && latestData.records.length > 0) {
            socket.emit('data_update', {
                type: 'refresh',
                timestamp: new Date().toISOString(),
                records: latestData.records,
                count: latestData.count
            });
        }
    });
    
    socket.on('disconnect', () => {
        console.log(`🏢 BRANCH OFFICE DISCONNECTED: ${branchId}`);
        connectedBranches.delete(branchId);
    });
});

// ============= START SERVER =============
server.listen(PORT, () => {
    console.log(`
    ═══════════════════════════════════════════════════════
    🌐 REMOTE RELAY SERVER (No UI - Pure API)
    ═══════════════════════════════════════════════════════
    📍 URL: http://localhost:${PORT}
    
    🔌 RECEIVE STREAM FROM LOCAL PC:
    └─ POST /realtimedata
    
    🏢 BRANCH OFFICE ENDPOINTS:
    ├─ GET  /api/data/all       - Get all data
    ├─ GET  /api/data/page      - Paginated data (?page=1&pageSize=100)
    ├─ POST /api/data/search    - Search records
    ├─ GET  /api/data/find/:field/:value - Find by field
    ├─ GET  /api/data/stats     - Get statistics
    ├─ GET  /api/health         - Health check
    └─ WS   /                   - WebSocket for real-time updates
    
    ⚡ Waiting for local server to send data...
    ═══════════════════════════════════════════════════════
    `);
});