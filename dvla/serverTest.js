// remote-server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(cors());

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI;

mongoose.connect(MONGODB_URI)
    .then(() => console.log('✅ Connected to MongoDB'))
    .catch(err => {
        console.error('❌ MongoDB connection error:', err.message);
        process.exit(1);
    });

// Schema for stored data
const recordSchema = new mongoose.Schema({
    tableName: { type: String, required: true, index: true },
    recordId: { type: String, required: true },
    data: { type: mongoose.Schema.Types.Mixed, required: true },
    hash: { type: String },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

recordSchema.index({ tableName: 1, recordId: 1 }, { unique: true });
recordSchema.index({ createdAt: 1 });

const Record = mongoose.model('Record', recordSchema);

// Helper function
function getRecordId(record) {
    if (record.id !== undefined && record.id !== null) return String(record.id);
    if (record.ID !== undefined && record.ID !== null) return String(record.ID);
    
    const idFields = ['Id', '_id', 'recordId', 'RecordId', 'rowId', 'RowId'];
    for (const field of idFields) {
        if (record[field] !== undefined && record[field] !== null) {
            return String(record[field]);
        }
    }
    return null;
}

// ============= API ENDPOINTS =============

// Get all data for a table
app.get('/api/data/:tableName', async (req, res) => {
    try {
        const { tableName } = req.params;
        console.log(`📊 Fetching all data for table: ${tableName}`);
        
        const records = await Record.find({ tableName }).sort({ createdAt: -1 });
        
        res.json({
            success: true,
            tableName,
            count: records.length,
            records: records.map(r => r.data),
            metadata: {
                lastUpdated: records.length > 0 ? records[0].updatedAt : null,
                totalRecords: records.length
            }
        });
    } catch (error) {
        console.error('Error fetching data:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get today's data for a table
app.get('/api/data/today/:tableName', async (req, res) => {
    try {
        const { tableName } = req.params;
        console.log(`📅 Fetching today's data for table: ${tableName}`);
        
        const startOfDay = new Date();
        startOfDay.setHours(0, 0, 0, 0);
        
        const endOfDay = new Date();
        endOfDay.setHours(23, 59, 59, 999);
        
        const records = await Record.find({
            tableName,
            createdAt: { $gte: startOfDay, $lte: endOfDay }
        }).sort({ createdAt: -1 });
        
        res.json({
            success: true,
            tableName,
            date: startOfDay,
            count: records.length,
            records: records.map(r => r.data),
            metadata: {
                startOfDay,
                endOfDay,
                totalRecords: records.length
            }
        });
    } catch (error) {
        console.error('Error fetching today\'s data:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get data by date range
app.get('/api/data/range/:tableName', async (req, res) => {
    try {
        const { tableName } = req.params;
        const { startDate, endDate } = req.query;
        
        if (!startDate || !endDate) {
            return res.status(400).json({ success: false, error: 'startDate and endDate are required' });
        }
        
        const start = new Date(startDate);
        const end = new Date(endDate);
        end.setHours(23, 59, 59, 999);
        
        const records = await Record.find({
            tableName,
            createdAt: { $gte: start, $lte: end }
        }).sort({ createdAt: -1 });
        
        res.json({
            success: true,
            tableName,
            startDate: start,
            endDate: end,
            count: records.length,
            records: records.map(r => r.data)
        });
    } catch (error) {
        console.error('Error fetching date range data:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get single record by ID
app.get('/api/data/:tableName/:recordId', async (req, res) => {
    try {
        const { tableName, recordId } = req.params;
        console.log(`🔍 Fetching record ${recordId} from ${tableName}`);
        
        const record = await Record.findOne({ tableName, recordId });
        
        if (!record) {
            return res.status(404).json({ success: false, error: 'Record not found' });
        }
        
        res.json({
            success: true,
            record: record.data,
            metadata: {
                createdAt: record.createdAt,
                updatedAt: record.updatedAt
            }
        });
    } catch (error) {
        console.error('Error fetching record:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get table statistics
app.get('/api/stats/:tableName', async (req, res) => {
    try {
        const { tableName } = req.params;
        console.log(`📈 Fetching stats for table: ${tableName}`);
        
        const totalCount = await Record.countDocuments({ tableName });
        
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const todayCount = await Record.countDocuments({
            tableName,
            createdAt: { $gte: today }
        });
        
        const lastWeek = new Date();
        lastWeek.setDate(lastWeek.getDate() - 7);
        const weekCount = await Record.countDocuments({
            tableName,
            createdAt: { $gte: lastWeek }
        });
        
        const lastMonth = new Date();
        lastMonth.setMonth(lastMonth.getMonth() - 1);
        const monthCount = await Record.countDocuments({
            tableName,
            createdAt: { $gte: lastMonth }
        });
        
        res.json({
            success: true,
            tableName,
            stats: {
                total: totalCount,
                today: todayCount,
                last7Days: weekCount,
                last30Days: monthCount
            },
            lastUpdated: new Date()
        });
    } catch (error) {
        console.error('Error fetching stats:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
        timestamp: new Date()
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`
    ════════════════════════════════════════════════════
    🚀 Remote Data Server is running!
    ════════════════════════════════════════════════════
    📡 Server URL: http://localhost:${PORT}
    📊 Get All Data: GET /api/data/:tableName
    📅 Get Today's Data: GET /api/data/today/:tableName
    📈 Get Stats: GET /api/stats/:tableName
    💚 Health: GET /health
    ════════════════════════════════════════════════════
    `);
});