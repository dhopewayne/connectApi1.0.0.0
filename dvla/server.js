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


function generateHash(record) {
    const crypto = require('crypto');
    const sortedRecord = {};
    Object.keys(record).sort().forEach(key => {
        sortedRecord[key] = record[key];
    });
    return crypto.createHash('md5').update(JSON.stringify(sortedRecord)).digest('hex');
}

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

// Add this to your remote server - accepts only changes, not full database
app.post('/api/sync/changes', async (req, res) => {
    try {
        const { tableName, changes } = req.body;
        
        console.log(`\n════════════════════════════════════════════`);
        console.log(`📥 SYNC CHANGES RECEIVED`);
        console.log(`Table: ${tableName}`);
        console.log(`Added: ${changes.added?.length || 0}`);
        console.log(`Updated: ${changes.updated?.length || 0}`);
        console.log(`Deleted: ${changes.deleted?.length || 0}`);
        
        if (!tableName || !changes) {
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid request: tableName and changes required' 
            });
        }
        
        const results = {
            added: 0,
            updated: 0,
            deleted: 0,
            errors: 0,
            ignored: 0
        };
        
        // Process added records
        if (changes.added && Array.isArray(changes.added)) {
            for (const record of changes.added) {
                try {
                    const recordId = getRecordId(record);
                    await Record.findOneAndUpdate(
                        { tableName, recordId },
                        {
                            tableName,
                            recordId,
                            data: record,
                            hash: generateHash(record),
                            updatedAt: new Date()
                        },
                        { upsert: true }
                    );
                    results.added++;
                    console.log(`  ✅ Added: ${recordId}`);
                } catch (error) {
                    console.error(`  ❌ Failed to add:`, error.message);
                    results.errors++;
                }
            }
        }
        
        // Process updated records (with date checking on remote side too)
        if (changes.updated && Array.isArray(changes.updated)) {
            for (const record of changes.updated) {
                try {
                    const recordId = getRecordId(record);
                    
                    // Check if the update is recent (less than 7 days old)
                    const timestampFields = ['updatedAt', 'updated_at', 'lastModified', 'modified', 'timestamp', 'date'];
                    let recordDate = null;
                    for (const field of timestampFields) {
                        if (record[field]) {
                            recordDate = new Date(record[field]);
                            break;
                        }
                    }
                    
                    const oneWeekAgo = new Date();
                    oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);
                    
                    if (recordDate && recordDate < oneWeekAgo) {
                        console.log(`  ⏭️ Ignored old update: ${recordId} (${recordDate})`);
                        results.ignored++;
                        continue;
                    }
                    
                    await Record.findOneAndUpdate(
                        { tableName, recordId },
                        {
                            tableName,
                            recordId,
                            data: record,
                            hash: generateHash(record),
                            updatedAt: new Date()
                        }
                    );
                    results.updated++;
                    console.log(`  ✅ Updated: ${recordId}`);
                } catch (error) {
                    console.error(`  ❌ Failed to update:`, error.message);
                    results.errors++;
                }
            }
        }
        
        // Process deleted records
        if (changes.deleted && Array.isArray(changes.deleted)) {
            for (const record of changes.deleted) {
                try {
                    const recordId = getRecordId(record);
                    await Record.deleteOne({ tableName, recordId });
                    results.deleted++;
                    console.log(`  ✅ Deleted: ${recordId}`);
                } catch (error) {
                    console.error(`  ❌ Failed to delete:`, error.message);
                    results.errors++;
                }
            }
        }
        
        console.log(`✅ Sync changes completed:`);
        console.log(`   Added: ${results.added}, Updated: ${results.updated}, Deleted: ${results.deleted}, Ignored: ${results.ignored}, Errors: ${results.errors}`);
        
        res.json({
            success: true,
            message: 'Changes synced successfully',
            stats: results,
            totalRecords: await Record.countDocuments({ tableName })
        });
        
    } catch (error) {
        console.error('❌ Sync error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
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