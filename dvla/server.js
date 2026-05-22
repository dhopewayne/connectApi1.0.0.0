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

// Store data by plate number for quick lookup and updates
let dataByPlate = new Map();

let connectedBranches = new Map();
let dataHistory = [];
const MAX_HISTORY = 50;

// Track which plates have been sent to each branch
let branchSentData = new Map(); // branchId -> Set of plate numbers

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
        description: 'Receives data from local PC and relays to branch offices with real-time updates',
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
        uniquePlates: dataByPlate.size,
        timestamp: new Date().toISOString()
    });
});

// ============= HELPER FUNCTION: Update or Add Record =============
function updateOrAddRecord(newRecord) {
    const plateNumber = newRecord.VehicleDetails?.RegistrationNumber || 
                       newRecord.RegistrationNumber || 
                       newRecord.PLATE_ID;
    
    if (!plateNumber) {
        console.log(`⚠️ Record has no plate number, adding as new`);
        latestData.records.unshift(newRecord);
        return true;
    }
    
    const existingIndex = latestData.records.findIndex(record => {
        const existingPlate = record.VehicleDetails?.RegistrationNumber || 
                            record.RegistrationNumber || 
                            record.PLATE_ID;
        return existingPlate === plateNumber;
    });
    
    if (existingIndex !== -1) {
        // Update existing record
        console.log(`🔄 Updating existing record for plate: ${plateNumber}`);
        latestData.records[existingIndex] = {
            ...latestData.records[existingIndex],
            ...newRecord,
            updatedAt: new Date().toISOString()
        };
        return false; // Return false to indicate this was an update, not a new record
    } else {
        // Add new record at the beginning
        console.log(`➕ Adding new record for plate: ${plateNumber}`);
        latestData.records.unshift({
            ...newRecord,
            addedAt: new Date().toISOString()
        });
        return true; // Return true to indicate this is a new record
    }
}

// ============= RECEIVE STREAM FROM LOCAL PC =============
app.post('/realtimedata', async (req, res) => {
    const { timestamp, records, count, source, table, isRefresh, plateNumber } = req.body;
    const sourceSecret = req.headers['x-source-secret'];
    const expectedSecret = process.env.REMOTE_SECRET;
    
    console.log(`\n📡 STREAM RECEIVED at ${new Date().toISOString()}`);
    console.log(`   Records: ${count || records?.length || 0}`);
    console.log(`   Source: ${source || 'local_pc'}`);
    console.log(`   Table: ${table || 'unknown'}`);
    if (isRefresh) console.log(`   Type: REFRESH for plate: ${plateNumber}`);
    
    // Verify secret if configured
    if (expectedSecret && sourceSecret !== expectedSecret) {
        console.log(`❌ Invalid secret - rejecting data`);
        return res.status(401).json({ error: 'Invalid secret' });
    }
    
    if (!records || records.length === 0) {
        console.log(`⚠️ No records in stream`);
        return res.json({ success: true, message: 'No data to process' });
    }
    
    let newRecordsCount = 0;
    let updatedRecordsCount = 0;
    const affectedPlates = [];
    
    // Process each record
    for (const record of records) {
        const isNew = updateOrAddRecord(record);
        if (isNew) {
            newRecordsCount++;
        } else {
            updatedRecordsCount++;
        }
        
        // Track affected plate
        const recordPlate = record.VehicleDetails?.RegistrationNumber || 
                           record.RegistrationNumber || 
                           record.PLATE_ID;
        if (recordPlate) {
            affectedPlates.push(recordPlate);
            dataByPlate.set(recordPlate, record);
        }
    }
    
    // Update latest data metadata
    latestData = {
        records: latestData.records,
        lastUpdate: new Date().toISOString(),
        source: source || 'local_pc',
        table: table || 'unknown',
        count: latestData.records.length,
        receivedAt: timestamp,
        newRecords: newRecordsCount,
        updatedRecords: updatedRecordsCount
    };
    
    // Add to history
    dataHistory.unshift({
        timestamp: new Date().toISOString(),
        recordCount: records.length,
        newRecords: newRecordsCount,
        updatedRecords: updatedRecordsCount,
        source: source || 'local_pc'
    });
    
    // Keep only last 50 updates
    if (dataHistory.length > MAX_HISTORY) {
        dataHistory.pop();
    }
    
    console.log(`✅ Data processed: ${newRecordsCount} new, ${updatedRecordsCount} updated`);
    console.log(`   Total records: ${latestData.count}`);
    
    // ============= REAL-TIME PUSH TO BRANCHES =============
    const broadcastPayload = {
        type: isRefresh ? 'record_update' : 'live_update',
        timestamp: new Date().toISOString(),
        records: records,
        count: records.length,
        newRecords: newRecordsCount,
        updatedRecords: updatedRecordsCount,
        source: source || 'local_pc',
        table: table || 'unknown',
        isRefresh: isRefresh || false,
        affectedPlates: affectedPlates
    };
    
    let branchesNotified = 0;
    
    // Broadcast to all connected branch offices via WebSocket
    for (const [branchId, branchSocket] of connectedBranches) {
        try {
            // Send the update
            branchSocket.emit('data_update', broadcastPayload);
            
            // Also send a specific event for the affected plates
            if (affectedPlates.length > 0) {
                branchSocket.emit('plates_updated', {
                    plates: affectedPlates,
                    timestamp: new Date().toISOString(),
                    isRefresh: isRefresh || false
                });
            }
            
            branchesNotified++;
        } catch (err) {
            console.error(`Error sending to branch ${branchId}:`, err.message);
        }
    }
    
    console.log(`📢 Broadcast to ${branchesNotified} connected branch offices`);
    
    res.json({ 
        success: true, 
        received: records.length,
        newRecords: newRecordsCount,
        updatedRecords: updatedRecordsCount,
        stored: true,
        branchesNotified: branchesNotified,
        timestamp: new Date().toISOString()
    });
});

// ============= BRANCH OFFICE ENDPOINTS =============

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
        table: latestData.table,
        newRecordsSinceLastRequest: latestData.newRecords || 0
    });
});

// Get data that has changed since a specific timestamp
app.get('/data/changes', async (req, res) => {
    const since = req.query.since;
    console.log(`🏢 Branch requested changes since: ${since}`);
    
    if (!since) {
        return res.status(400).json({ error: 'since parameter required (ISO timestamp)' });
    }
    
    const sinceTime = new Date(since);
    
    // Find records that were added or updated after the timestamp
    const changedRecords = latestData.records.filter(record => {
        const addedAt = record.addedAt ? new Date(record.addedAt) : null;
        const updatedAt = record.updatedAt ? new Date(record.updatedAt) : null;
        return (addedAt && addedAt > sinceTime) || (updatedAt && updatedAt > sinceTime);
    });
    
    res.json({
        success: true,
        records: changedRecords,
        count: changedRecords.length,
        since: since,
        currentCount: latestData.count,
        lastUpdate: latestData.lastUpdate
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
                const recordValue = getNestedValue(record, key);
                return String(recordValue).toLowerCase() === String(value).toLowerCase();
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

// Helper to get nested object values
function getNestedValue(obj, path) {
    return path.split('.').reduce((current, key) => current?.[key], obj);
}

// Get single record by plate number
app.get('/data/plate/:plateNumber', async (req, res) => {
    const { plateNumber } = req.params;
    
    console.log(`🏢 Branch requested plate: ${plateNumber}`);
    
    const record = dataByPlate.get(plateNumber);
    
    if (record) {
        res.json({
            success: true,
            record: record,
            found: true
        });
    } else {
        res.json({
            success: true,
            found: false,
            message: `No record found for plate: ${plateNumber}`
        });
    }
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
    
    const matchedRecords = latestData.records.filter(record => {
        const recordValue = getNestedValue(record, field);
        return String(recordValue).toUpperCase() === String(value).toUpperCase();
    });
    
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
    
    // Get all unique keys from all records
    const allKeys = new Set();
    latestData.records.forEach(record => {
        Object.keys(record).forEach(key => allKeys.add(key));
    });
    
    const columns = Array.from(allKeys);
    
    const stats = {
        totalRecords: latestData.count,
        columns: columns,
        columnCount: columns.length,
        lastUpdate: latestData.lastUpdate,
        source: latestData.source,
        table: latestData.table,
        uniquePlates: dataByPlate.size
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

// WebSocket connection status endpoint
app.get('/data/connections', async (req, res) => {
    const branches = [];
    for (const [id, socket] of connectedBranches) {
        branches.push({
            id: id,
            connectedAt: socket.connectedAt || 'unknown',
            ip: socket.handshake?.address || 'unknown'
        });
    }
    
    res.json({
        success: true,
        totalConnected: connectedBranches.size,
        branches: branches
    });
});

// ============= WEBSOCKET FOR BRANCH OFFICES =============
io.on('connection', (socket) => {
    const branchId = socket.id;
    const clientIp = socket.handshake.address;
    
    console.log(`🏢 BRANCH OFFICE CONNECTED: ${branchId} from ${clientIp}`);
    
    // Store connection metadata
    socket.connectedAt = new Date().toISOString();
    connectedBranches.set(branchId, socket);
    
    // Initialize sent data tracking for this branch
    branchSentData.set(branchId, new Set());
    
    // Send current status and data immediately
    if (latestData.records && latestData.records.length > 0) {
        socket.emit('connected', {
            status: 'connected',
            message: 'Connected to data relay server',
            recordCount: latestData.count,
            lastUpdate: latestData.lastUpdate,
            hasData: true,
            willReceiveRealTimeUpdates: true
        });
        
        // Send current data
        socket.emit('data_update', {
            type: 'initial',
            timestamp: new Date().toISOString(),
            records: latestData.records,
            count: latestData.count,
            source: latestData.source,
            totalRecords: latestData.count
        });
        
        console.log(`📤 Sent initial data (${latestData.count} records) to branch ${branchId}`);
    } else {
        socket.emit('connected', {
            status: 'connected',
            message: 'Connected to data relay server - waiting for data from local PC',
            hasData: false,
            willReceiveRealTimeUpdates: true
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
                const recordValue = getNestedValue(record, key);
                return String(recordValue).toLowerCase().includes(String(value).toLowerCase());
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
    
    // Handle single plate request
    socket.on('get_plate', (plateNumber) => {
        console.log(`🔍 Branch ${branchId} requested plate: ${plateNumber}`);
        
        const record = dataByPlate.get(plateNumber);
        
        socket.emit('plate_data', {
            plateNumber: plateNumber,
            record: record || null,
            found: !!record,
            timestamp: new Date().toISOString()
        });
    });
    
    // Handle refresh request - sends only new/changed data
    socket.on('refresh_request', (sinceTimestamp) => {
        console.log(`🔄 Branch ${branchId} requested refresh since: ${sinceTimestamp || 'all'}`);
        
        if (!latestData.records || latestData.records.length === 0) {
            socket.emit('refresh_response', {
                records: [],
                count: 0,
                message: 'No data available'
            });
            return;
        }
        
        let recordsToSend = latestData.records;
        
        // If timestamp provided, only send records added/updated after that time
        if (sinceTimestamp) {
            const sinceTime = new Date(sinceTimestamp);
            recordsToSend = latestData.records.filter(record => {
                const addedAt = record.addedAt ? new Date(record.addedAt) : null;
                const updatedAt = record.updatedAt ? new Date(record.updatedAt) : null;
                return (addedAt && addedAt > sinceTime) || (updatedAt && updatedAt > sinceTime);
            });
        }
        
        socket.emit('refresh_response', {
            records: recordsToSend,
            count: recordsToSend.length,
            totalRecords: latestData.count,
            since: sinceTimestamp || null,
            timestamp: new Date().toISOString()
        });
        
        console.log(`📤 Sent ${recordsToSend.length} refreshed records to branch ${branchId}`);
    });
    
    // Subscribe to specific plate updates
    socket.on('subscribe_plate', (plateNumber) => {
        if (!socket.subscribedPlates) {
            socket.subscribedPlates = new Set();
        }
        socket.subscribedPlates.add(plateNumber);
        console.log(`📡 Branch ${branchId} subscribed to plate: ${plateNumber}`);
        
        // Send current data for this plate immediately
        const record = dataByPlate.get(plateNumber);
        if (record) {
            socket.emit('plate_update', {
                plateNumber: plateNumber,
                record: record,
                type: 'subscription_data',
                timestamp: new Date().toISOString()
            });
        }
    });
    
    // Unsubscribe from plate updates
    socket.on('unsubscribe_plate', (plateNumber) => {
        if (socket.subscribedPlates) {
            socket.subscribedPlates.delete(plateNumber);
            console.log(`📡 Branch ${branchId} unsubscribed from plate: ${plateNumber}`);
        }
    });
    
    // Handle ping for connection health
    socket.on('ping', () => {
        socket.emit('pong', { 
            timestamp: new Date().toISOString(),
            serverTime: new Date().toISOString()
        });
    });
    
    socket.on('disconnect', () => {
        console.log(`🏢 BRANCH OFFICE DISCONNECTED: ${branchId}`);
        connectedBranches.delete(branchId);
        branchSentData.delete(branchId);
    });
});

// Broadcast updates to subscribed clients when data changes
function broadcastToSubscribers(plateNumber, record) {
    for (const [branchId, socket] of connectedBranches) {
        if (socket.subscribedPlates && socket.subscribedPlates.has(plateNumber)) {
            socket.emit('plate_update', {
                plateNumber: plateNumber,
                record: record,
                type: 'real_time_update',
                timestamp: new Date().toISOString()
            });
        }
    }
}

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
    ├─ GET  /data/all           - Get all current data
    ├─ GET  /data/changes?since=timestamp - Get changed data only
    ├─ GET  /data/page          - Get paginated data
    ├─ POST /data/search        - Search/filter records
    ├─ GET  /data/plate/:plateNumber - Get specific plate
    ├─ GET  /data/find/:field/:value - Find by field
    ├─ GET  /data/stats         - Get statistics
    ├─ GET  /data/history       - Get update history
    ├─ GET  /data/export        - Export all data as JSON
    ├─ GET  /data/connections   - View connected branches
    ├─ GET  /health             - Health check
    └─ WS   /                   - WebSocket for real-time updates
    
    📡 REAL-TIME FEATURES:
    ├─ Automatic push on new data (no page refresh needed)
    ├─ Plate subscription for focused updates
    ├─ Incremental refresh with since timestamp
    └─ Live filter updates
    
    📊 Current Status:
    ├─ Data received: ${latestData.count} records
    ├─ Connected branches: ${connectedBranches.size}
    ├─ Unique plates: ${dataByPlate.size}
    └─ History size: ${dataHistory.length}
    
    ⚡ Waiting for local PC to send data via POST /realtimedata
    ═══════════════════════════════════════════════════════
    `);
});