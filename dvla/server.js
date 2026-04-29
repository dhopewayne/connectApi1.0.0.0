// remote-server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const crypto = require('crypto');
const { table } = require('console');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(cors());

// ============= SCHEMA AND MODEL =============
// FIX #1 (from prior review): Schema defined BEFORE model creation

const recordSchema = new mongoose.Schema({
    tableName: { type: String, required: true, index: true },
    recordId: { type: String, required: true },
    data: { type: mongoose.Schema.Types.Mixed, required: true },
    hash: { type: String },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});  


const monitoringConfigSchema = new mongoose.Schema({
    tableName: { type: String, required: true, unique: true },
    monitoringColumn: { type: String, required: true },
    timestampColumn: { type: String, default: '' }  ,   
    updatedAt: { type: Date, default: Date.now }
}); 

const MonitoringConfig = mongoose.model('MonitoringConfig', monitoringConfigSchema);

recordSchema.index({ tableName: 1, recordId: 1 }, { unique: true });
recordSchema.index({ createdAt: 1 });
recordSchema.index({ updatedAt: 1 });

const Record = mongoose.model('Record', recordSchema);

// ============= MONGODB CONNECTION =============

const MONGODB_URI = process.env.MONGODB_URI;

mongoose.connect(MONGODB_URI)
    .then(() => console.log('✅ Connected to MongoDB'))
    .catch(err => {
        console.error('❌ MongoDB connection error:', err.message);
        process.exit(1);
    });

// ============= HELPERS =============

function generateHash(record) {
    const sortedRecord = {};
    Object.keys(record).sort().forEach(key => {
        sortedRecord[key] = record[key];
    });
    return crypto.createHash('md5').update(JSON.stringify(sortedRecord)).digest('hex');
}

function getRecordId(record) {
    if (record.id !== undefined && record.id !== null) return String(record.id);
    if (record.ID !== undefined && record.ID !== null) return String(record.ID);
    if (record.AUTOID !== undefined && record.AUTOID !== null) return String(record.AUTOID);

    const idFields = ['Id', '_id', 'recordId', 'RecordId', 'rowId', 'RowId'];
    for (const field of idFields) {
        if (record[field] !== undefined && record[field] !== null) {
            return String(record[field]);
        }
    }
    return null;
}

// ============= API ENDPOINTS =============

// Get all data for a table (with optional ?ids= filter)
app.get('/api/data/:tableName', async (req, res) => {
    try {
        const { tableName } = req.params;
        const { ids } = req.query;

        console.log(`📊 Fetching data for table: ${tableName}${ids ? ` (filtered: ${ids.split(',').length} IDs)` : ''}`);  




        // FIX #1: Support filtering by IDs via query param
        const query = { tableName };
        if (ids) {
            const idArray = ids.split(',').map(id => id.trim()).filter(Boolean);
            if (idArray.length > 0) {
                query.recordId = { $in: idArray };
            }
        }

        const records = await Record.find(query).sort({ createdAt: -1 });

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



async function getTableLastIdAndTimestamp(tableName) { 
    const monitoringConfig = await MonitoringConfig.findOne({ tableName }).lean();
    const monitoringColumn = monitoringConfig?.monitoringColumn;
    const timestampColumn = monitoringConfig?.timestampColumn;   // e.g. "UpdateTime", "SyncTime", etc.
    if (!monitoringColumn) {
        throw new Error('monitoringColumn not configured for this table');
    }

    const sortField = timestampColumn && timestampColumn !== '' ? `data.${timestampColumn}` : 'updatedAt';
    const lastRecord = await Record.findOne({ tableName }).sort({ [sortField]: -1 }).lean();
    if (!lastRecord) {
        return { lastId: null, timestamp: null };
    }
    const lastIdValue = lastRecord.data?.[monitoringColumn];
    const timestampValue = timestampColumn
        ? lastRecord.data?.[timestampColumn]
        : lastRecord.updatedAt;
    return { lastId: lastIdValue != null ? String(lastIdValue) : null, timestamp: timestampValue };
}


// Get last record based on monitoringColumn + timestampColumn (or updatedAt fallback)
app.get('/api/data/:tableName/last-id', async (req, res) => {
    try {
        const { tableName } = req.params;

        // Load monitoring configuration
        const monitoringConfig = await MonitoringConfig.findOne({ tableName }).lean();
        
        const monitoringColumn = monitoringConfig?.monitoringColumn;
        const timestampColumn = monitoringConfig?.timestampColumn;   // e.g. "UpdateTime", "SyncTime", etc.

        if (!monitoringColumn) {
            return res.status(400).json({
                success: false,
                error: 'monitoringColumn not configured for this table'
            });
        }

        // Determine which timestamp field to sort by
        const sortField = timestampColumn && timestampColumn !== '' 
            ? `data.${timestampColumn}` 
            : 'updatedAt';

        // Find the most recent record based on the timestamp
        const lastRecord = await Record.findOne({ tableName })
            .sort({ [sortField]: -1 })   // newest first
            .lean();

        if (!lastRecord) {
            return res.json({
                success: true,
                lastId: null,
                timestamp: null,
                lastRecord: null
            });
        }

        const lastIdValue = lastRecord.data?.[monitoringColumn];
        const timestampValue = timestampColumn 
            ? lastRecord.data?.[timestampColumn] 
            : lastRecord.updatedAt;

        console.log(`🆔 Last record for ${tableName} | MonitoringColumn: ${monitoringColumn} = ${lastIdValue} | Timestamp: ${timestampValue}`);

        res.json({
            success: true,
            lastId: lastIdValue != null ? String(lastIdValue) : null,
            timestamp: timestampValue,
            monitoringColumn,
            timestampColumn: timestampColumn || 'updatedAt',
            lastRecord: lastRecord.data   // full record so local server can extract anything
        });

    } catch (error) {
        console.error('Error fetching last-id:', error);
        res.status(500).json({ 
            success: false, 
            error: error.message 
        });
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
            metadata: { startOfDay, endOfDay, totalRecords: records.length }
        });
    } catch (error) {
        console.error("Error fetching today's data:", error);
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
            metadata: { createdAt: record.createdAt, updatedAt: record.updatedAt }
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
        const todayCount = await Record.countDocuments({ tableName, createdAt: { $gte: today } });

        const lastWeek = new Date();
        lastWeek.setDate(lastWeek.getDate() - 7);
        const weekCount = await Record.countDocuments({ tableName, createdAt: { $gte: lastWeek } });

        const lastMonth = new Date();
        lastMonth.setMonth(lastMonth.getMonth() - 1);
        const monthCount = await Record.countDocuments({ tableName, createdAt: { $gte: lastMonth } });   
 

        const TableIdAndTimestamp = await getTableLastIdAndTimestamp(tableName);  


        console.log('tableId and timestamp response '  ,  TableIdAndTimestamp);

        console.log(`Stats for ${tableName} | Total: ${totalCount} | Today: ${todayCount} | Last 7 Days: ${weekCount} | Last 30 Days: ${monthCount} | LastId: ${TableIdAndTimestamp.lastId} | Timestamp: ${TableIdAndTimestamp.timestamp}`); 

        res.json({
            success: true,
            tableName,
            stats: {
                total: totalCount,
                today: todayCount,
                last7Days: weekCount,
                last30Days: monthCount  
            }, 
            tableIdAndTimestamp: TableIdAndTimestamp, 
            lastUpdated: new Date()
        });
    } catch (error) {
        console.error('Error fetching stats:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Receive and process sync changes from local server
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

        const results = { added: 0, updated: 0, deleted: 0, errors: 0, ignored: 0 };

        // Process added records
        if (changes.added && Array.isArray(changes.added)) {
            for (const record of changes.added) {
                try {
                    const recordId = getRecordId(record);
                    if (!recordId) {
                        console.log(`  ⚠️ Could not extract ID from added record`);
                        results.errors++;
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
                        },
                        { upsert: true, new: true }
                    );
                    results.added++;
                    // console.log(`  ✅ Added: ${recordId}`);
                } catch (error) {
                    console.error(`  ❌ Failed to add:`, error.message);
                    results.errors++;
                }
            }
        }

        // Process updated records
        // Local server sends plain records (not {old, new}) — pushChangesInBatches handles this
        if (changes.updated && Array.isArray(changes.updated)) {
            for (const updateItem of changes.updated) {
                try {
                    // Handle both formats defensively: plain record or {old, new}
                    const record = updateItem.new !== undefined ? updateItem.new : updateItem;

                    const recordId = getRecordId(record);
                    if (!recordId) {
                        console.log(`  ⚠️ Could not extract ID from updated record`);
                        results.errors++;
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
                        },
                        { upsert: true, new: true }
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
                    if (!recordId) {
                        console.log(`  ⚠️ Could not extract ID from deleted record`);
                        results.errors++;
                        continue;
                    }
                    await Record.deleteOne({ tableName, recordId });
                    results.deleted++;
                    console.log(`  ✅ Deleted: ${recordId}`);
                } catch (error) {
                    console.error(`  ❌ Failed to delete:`, error.message);
                    results.errors++;
                }
            }
        }

        const totalRecords = await Record.countDocuments({ tableName });

        console.log(`✅ Sync results: +${results.added} ~${results.updated} -${results.deleted} ✗${results.errors}`);
        console.log(`   Total records in remote DB: ${totalRecords}`);
        console.log(`════════════════════════════════════════════\n`);

        res.json({
            success: true,
            message: 'Changes synced successfully',
            stats: results,
            totalRecords
        });

    } catch (error) {
        console.error('❌ Sync error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});  
 

 
app.get('/api/data/:tableName/last-id', async (req, res) => {
    try {
        const { tableName } = req.params;
        // so the local server can extract whatever column it needs
        const record = await Record.findOne({ tableName }).sort({ updatedAt: -1 }).lean();
        res.json({
            success: true,
            lastRecord: record?.data || null
        });
    } catch (error) {
        console.error('Error fetching last record:', error);
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

// ============= START SERVER =============

app.listen(PORT, () => {
    console.log(`
    ════════════════════════════════════════════════════
    🚀 Remote Data Server is running!
    ════════════════════════════════════════════════════
    📡 Server URL: http://localhost:${PORT}
    📊 Get All Data:      GET  /api/data/:tableName
    🔍 Get By IDs:        POST /api/data/:tableName/by-ids
    📅 Get Today's Data:  GET  /api/data/today/:tableName
    📈 Get Stats:         GET  /api/stats/:tableName
    🔄 Receive Changes:   POST /api/sync/changes
    💚 Health:            GET  /health
    ════════════════════════════════════════════════════
    `);
}); 


