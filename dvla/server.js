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

// ============= ROOT ENDPOINT =============
app.get('/', (req, res) => {
    res.json({
        name: 'Remote Data Relay Server',
        status: 'online',
        version: '1.0.0',
        description: 'Receives data from local PC and relays to branch offices',
        endpoints: {
            receive_stream: 'POST /realtimedata (for local PC)',
            get_all_data: 'GET /data/all',
            get_paginated: 'GET /data/page?page=1&pageSize=100',
            search: 'POST /data/search',
            find_by_field: 'GET /data/find/:field/:value',
            stats: 'GET /data/stats',
            history: 'GET /data/history',
            health: 'GET /data/health'
        },
        websocket: 'ws://' + req.get('host'),
        timestamp: new Date().toISOString()
    });
});

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
app.post('/realtimedata', async (req, res) => {
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

// ============= BRANCH OFFICE ENDPOINTS (UNCHANGED) =============

// Get all current data
app.get('/data/all', async (req, res) => {
    console.log(`🏢 Branch requested all data`);
    
    if (!latestData.records || latestData.records.length === 0) {
        return res.json({
            success: true,
            records: [],
            count: 0,
            message: 'No data available yet. Waiting for local PC to send data.'
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
app.get('/data/page', async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const pageSize = Math.min(parseInt(req.query.pageSize) || 100, 1000);
    const startIndex = (page - 1) * pageSize;
    
    console.log(`🏢 Branch requested page ${page}, size ${pageSize}`);
    
    if (!latestData.records || latestData.records.length === 0) {
        return res.json({
            success: true,
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
    
    console.log(`🏢 BRANCH OFFICE CONNECTED: ${branchId} from ${clientIp}`);
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
server.listen(PORT, () => {
    console.log(`
    ═══════════════════════════════════════════════════════
    🌐 REMOTE RELAY SERVER (Cloud - No Local DB)
    ═══════════════════════════════════════════════════════
    📍 Public URL:       ${process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`}
    
    🔌 RECEIVE STREAM FROM LOCAL PC:
    └─ POST /realtimedata
    
    🏢 BRANCH OFFICE ENDPOINTS:
    ├─ GET  /data/all       - Get all current data
    ├─ GET  /data/page      - Get paginated data
    ├─ POST /data/search    - Search/filter records
    ├─ GET  /data/find/:field/:value - Find by field
    ├─ GET  /data/stats     - Get statistics
    ├─ GET  /data/history   - Get update history
    ├─ GET  /data/export    - Export all data as JSON
    ├─ GET  /health         - Health check
    └─ WS   /               - WebSocket for real-time updates
    
    📡 REAL-TIME FEATURE:
    └─ New data automatically pushed via WebSocket (no page refresh needed!)
    
    📊 Current Status:
    ├─ Data received: ${latestData.count} records
    ├─ Connected branches: ${connectedBranches.size}
    └─ History size: ${dataHistory.length}
    
    ⚡ Waiting for local PC to send data via POST /realtimedata
    ═══════════════════════════════════════════════════════
    `);
});