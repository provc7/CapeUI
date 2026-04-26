require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const FormData = require('form-data');
const axios = require('axios');
// Malware Bazaar proxy config
const MB_AUTH_KEY = process.env.MB_AUTH_KEY || 'c142633e2abd97535582df9842fbfbbfcb7298e243d2a4ad';
const MB_API_URL = process.env.MB_API_URL || 'https://mb-api.abuse.ch/api/v1/';
const mongoose = require('mongoose');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const fsp = require('fs/promises');

const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');
const xss = require('xss-clean');

const app = express();

// Global state for submission restriction
let submissionRestrictionEnabled = true;

// Security Headers
app.use(helmet({
    contentSecurityPolicy: false, // Disable CSP for simplicity in this dev setup, or configure strictly
}));

// Prevent Parameter Pollution
app.use(hpp());

// Data Sanitization against NoSQL Query Injection
app.use(mongoSanitize());

// Data Sanitization against XSS
app.use(xss());

app.use(cors());
app.use(express.json({ limit: '10kb' })); // Limit body size
app.use(express.urlencoded({ extended: true }));

// Global Request Logger to server.log
app.use(async (req, res, next) => {
    const start = Date.now();
    res.on('finish', async () => {
        const duration = Date.now() - start;
        await writeLog('../logs/server_activity.log', {
            type: 'request',
            method: req.method,
            url: req.originalUrl,
            status: res.statusCode,
            ip: req.ip,
            duration: `${duration}ms`
        });
    });
    next();
});

// Basic rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later'
});
app.use(limiter);

const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 50 * 1024 * 1024 } // 50MB limit
});
const PORT = process.env.PORT || 3000;

// CAPE API endpoints
const CAPE_API_BASE = process.env.CAPE_API_BASE || 'http://10.20.8.79:8000';
const CAPE_API_UPLOAD_URL = `${CAPE_API_BASE}/apiv2/tasks/create/file/`;

// Logging helpers (JSONL files in ./logs)
const LOG_DIR = path.join(__dirname, 'logs');
function ensureLogDir() {
    try { if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true }); } catch (_) { }
}
ensureLogDir();

// Reports directory for visualiser input files
const REPORTS_DIR = path.join(__dirname, 'reports');
function ensureReportsDir() {
    try { if (!fs.existsSync(REPORTS_DIR)) fs.mkdirSync(REPORTS_DIR, { recursive: true }); } catch (_) { }
}
ensureReportsDir();

async function writeLog(fileName, record) {
    const line = JSON.stringify({ ts: new Date().toISOString(), ...record }) + '\n';
    try { await fsp.appendFile(path.join(LOG_DIR, fileName), line, 'utf8'); } catch (e) { console.error('Log write error:', e.message); }
}

function userFromReq(req) {
    return req.user?.username || 'anonymous';
}

// MongoDB connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/cape';
mongoose.connect(MONGODB_URI)
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error('MongoDB connection error:', err.message));

// Submission model for storing history
const submissionSchema = new mongoose.Schema({
    taskId: { type: String, required: true },
    filename: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    status: { type: String, default: 'pending' },
    userId: { type: String, required: true }, // username of the user who submitted
    package: { type: String, default: 'exe' },
    timeout: { type: Number, default: 300 },
    priority: { type: Number, default: 1 },
    size: Number,
    mimetype: String
});

const Submission = mongoose.model('Submission', submissionSchema);

// JWT helpers
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
function signTokens(user) {
    const accessToken = jwt.sign({ sub: user.sub, role: user.role, username: user.username }, JWT_SECRET, { expiresIn: '12h' });
    return { accessToken };
}

function authMiddleware(req, res, next) {
    const header = req.headers['authorization'] || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing token' });
    try {
        const payload = jwt.verify(token, JWT_SECRET);
        req.user = payload;
        return next();
    } catch (e) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

// User model for storing login history
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true }, // Roll number for students
    email: { type: String, unique: true, sparse: true }, // Optional email (unique index exists)
    role: { type: String, default: 'student' },
    createdAt: { type: Date, default: Date.now },
    lastLogin: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);



// Login History Model
const loginHistorySchema = new mongoose.Schema({
    username: { type: String, required: true, index: true },
    role: { type: String, required: true },
    ip: String,
    timestamp: { type: Date, default: Date.now },
    userAgent: String
});
const LoginHistory = mongoose.model('LoginHistory', loginHistorySchema);

// Auth routes (fixed credential)
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'root';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || null; // plaintext fallback
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || null; // argon2 hash optional
const STUDENT_PASSWORD = process.env.STUDENT_PASSWORD || 'student123';

function requireAdmin(req, res, next) {
    if (req.user && req.user.role === 'admin') {
        return next();
    }
    return res.status(403).json({ error: 'Access denied: Admins only' });
}

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        console.log('Login attempt:', { username }); // Don't log passwords
        if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

        // Basic brute force protection (sleep)
        await new Promise(r => setTimeout(r, 500));

        let role = 'user';
        let isAuthenticated = false;

        // Check for Student Login (10-digit roll number)
        if (/^\d{10}$/.test(username)) {
            if (password === STUDENT_PASSWORD) {
                role = 'student';
                isAuthenticated = true;

                // Persist student to MongoDB
                try {
                    await User.findOneAndUpdate(
                        { username },
                        {
                            $setOnInsert: {
                                username,
                                role: 'student',
                                createdAt: new Date(),
                                email: `${username}@student.local` // Generate unique email to satisfy unique index
                            },
                            $set: { lastLogin: new Date() }
                        },
                        { upsert: true, new: true }
                    );
                } catch (dbErr) {
                    console.error('Error saving user to DB:', dbErr.message);
                    // Don't block login if DB write fails, but log it
                }

                await writeLog('auth.log', { type: 'login_success', ip: req.ip, username, role });
            }
        }
        // Check for Admin Login
        else if (username === ADMIN_USERNAME) {
            if (ADMIN_PASSWORD_HASH) {
                try {
                    isAuthenticated = await argon2.verify(ADMIN_PASSWORD_HASH, password);
                } catch (_) { isAuthenticated = false; }
            } else if (ADMIN_PASSWORD) {
                isAuthenticated = password === ADMIN_PASSWORD;
            }
            if (isAuthenticated) {
                role = 'admin';
                await writeLog('auth.log', { type: 'login_success', ip: req.ip, username, role });
            }
        }

        if (isAuthenticated) {
            // Record Login History
            try {
                await LoginHistory.create({
                    username,
                    role,
                    ip: req.ip,
                    userAgent: req.headers['user-agent']
                });
            } catch (histErr) {
                console.error('Error saving login history:', histErr.message);
            }
        }

        if (!isAuthenticated) {
            await writeLog('auth.log', { type: 'login_failed', ip: req.ip, username });
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const tokens = signTokens({ sub: username, role, username });
        return res.json({ user: { username, role }, ...tokens });
    } catch (err) {
        console.error('Login error:', err.message);
        await writeLog('auth.log', { type: 'login_error', ip: req.ip, error: err.message });
        return res.status(500).json({ error: 'Login failed' });
    }
});

// Serve static files (index.html)
app.use(express.static(__dirname));

// List submissions for the current user
app.get('/api/submissions', authMiddleware, async (req, res) => {
    try {
        const submissions = await Submission.find({ userId: req.user.username })
            .sort({ timestamp: -1 })
            .limit(100); // Optional limit
        res.json(submissions);
    } catch (error) {
        console.error('Error fetching submissions:', error);
        res.status(500).json({ error: 'Failed to fetch submission history' });
    }
});

// Bulk-refresh statuses of non-terminal submissions from CAPE API
app.post('/api/submissions/refresh', authMiddleware, async (req, res) => {
    try {
        const submissions = await Submission.find({ userId: req.user.username })
            .sort({ timestamp: -1 })
            .limit(100)
            .lean();

        const terminalStatuses = ['reported', 'completed', 'success', 'error', 'failed', 'timedout'];
        const pendingSubs = submissions.filter(s =>
            s.taskId && !terminalStatuses.includes((s.status || '').toLowerCase())
        );

        let updated = 0;
        if (pendingSubs.length > 0) {
            const results = await Promise.allSettled(
                pendingSubs.map(async (sub) => {
                    try {
                        const url = `${CAPE_API_BASE}/apiv2/tasks/status/${sub.taskId}`;
                        const response = await axios.get(url, { timeout: 5000 });
                        const rawData = response.data?.data;
                        const status = typeof rawData === 'string' ? rawData : (rawData?.status || response.data?.status);
                        if (status) {
                            const lowerStatus = status.toLowerCase();
                            if (lowerStatus !== (sub.status || '').toLowerCase()) {
                                await Submission.findOneAndUpdate(
                                    { taskId: sub.taskId, userId: req.user.username },
                                    { status: lowerStatus }
                                );
                                updated++;
                            }
                        }
                    } catch (_) {
                        // Ignore individual CAPE API failures
                    }
                })
            );
        }

        // Return the refreshed submissions
        const refreshed = await Submission.find({ userId: req.user.username })
            .sort({ timestamp: -1 })
            .limit(100);
        res.json({ updated, submissions: refreshed });
    } catch (error) {
        console.error('Error refreshing submission statuses:', error);
        res.status(500).json({ error: 'Failed to refresh statuses' });
    }
});

// Update submission status
app.put('/api/submissions/:taskId', authMiddleware, async (req, res) => {
    try {
        const { taskId } = req.params;
        const { status } = req.body;
        if (!status) return res.status(400).json({ error: 'Status required' });

        const submission = await Submission.findOneAndUpdate(
            { taskId, userId: req.user.username },
            { status },
            { new: true }
        );

        if (!submission) return res.status(404).json({ error: 'Submission not found' });
        res.json(submission);
    } catch (error) {
        console.error('Error updating submission:', error);
        res.status(500).json({ error: 'Failed to update submission' });
    }
});

// Delete a submission
app.delete('/api/submissions/:taskId', authMiddleware, async (req, res) => {
    try {
        const { taskId } = req.params;
        const result = await Submission.findOneAndDelete({ taskId, userId: req.user.username });
        if (!result) return res.status(404).json({ error: 'Submission not found' });
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting submission:', error);
        res.status(500).json({ error: 'Failed to delete submission' });
    }
});

// Handle file upload to CAPE API (protected)
app.post('/api/upload', authMiddleware, upload.single('file'), async (req, res) => {
    try {
        const file = req.file;
        const { package: packageType, timeout, priority } = req.body;

        if (!file) {
            await writeLog('tasks.log', { type: 'submit_missing_file', ip: req.ip, user: userFromReq(req) });
            return res.status(400).json({ error: 'No file provided' });
        }

        // Validate inputs
        const validPackages = ['exe', 'dll', 'zip', 'apk', 'office', 'pdf', 'browser', 'chrome', 'firefox', 'ie', 'auto'];
        const pkg = (packageType && validPackages.includes(packageType)) ? packageType : 'exe';
        const tm = Math.min(Math.max(parseInt(timeout) || 300, 100), 300); // 100s to 300s
        // Only admin users can set custom priority; students are forced to 1
        const prio = (req.user && (req.user.role === 'admin' || req.user.role === 'root'))
            ? Math.min(Math.max(parseInt(priority) || 1, 1), 5)
            : 1;

        // Rate limit check
        if (submissionRestrictionEnabled && req.user && req.user.role !== 'admin' && req.user.role !== 'root') {
            const fiveHoursAgo = new Date(Date.now() - 5 * 60 * 60 * 1000);
            const recentSubmissionsCount = await Submission.countDocuments({
                userId: req.user.username,
                timestamp: { $gte: fiveHoursAgo }
            });
            if (recentSubmissionsCount >= 5) {
                await writeLog('tasks.log', { type: 'submit_rate_limited', ip: req.ip, user: userFromReq(req) });
                return res.status(429).json({ error: 'Submission limit reached. Max 5 submissions per 5 hours.' });
            }
        }

        // Create form data to forward to CAPE API
        const formData = new FormData();
        formData.append('file', file.buffer, {
            filename: file.originalname,
            contentType: file.mimetype
        });
        formData.append('package', pkg);
        formData.append('timeout', String(tm));
        formData.append('priority', String(prio));

        await writeLog('tasks.log', {
            type: 'submit_attempt', ip: req.ip, user: userFromReq(req),
            filename: file.originalname, size: file.size, mimetype: file.mimetype,
            package: pkg, timeout: tm, priority: prio
        });

        // Forward request to CAPE API
        const response = await axios.post(CAPE_API_UPLOAD_URL, formData, {
            headers: {
                ...formData.getHeaders()
            },
            maxContentLength: Infinity,
            maxBodyLength: Infinity
        });

        // Log the response for debugging
        console.log('CAPE API Upload Response:', JSON.stringify(response.data, null, 2));
        try {
            const taskIds = response.data?.data?.task_ids || response.data?.task_ids || [];
            const taskId = taskIds[0]; // Assuming single file upload

            // Save submission to MongoDB
            if (taskId) {
                const submission = new Submission({
                    taskId,
                    filename: file.originalname,
                    userId: req.user.username,
                    package: pkg,
                    timeout: tm,
                    priority: prio,
                    size: file.size,
                    mimetype: file.mimetype,
                    status: 'pending'
                });
                await submission.save();
            }

            await writeLog('tasks.log', { type: 'submit_success', ip: req.ip, user: userFromReq(req), filename: file.originalname, taskIds });
        } catch (error) {
            console.error('Error saving submission:', error);
        }

        res.json(response.data);
    } catch (error) {
        console.error('Error uploading to CAPE API:', error.message);
        await writeLog('tasks.log', { type: 'submit_error', ip: req.ip, user: userFromReq(req), error: error.message, details: error.response?.data });
        res.status(error.response?.status || 500).json({
            error: error.message,
            details: error.response?.data || 'Unknown error'
        });
    }
});

// Handle task status lookup (protected)
app.get('/api/task/:taskId', authMiddleware, async (req, res) => {
    try {
        const { taskId } = req.params;
        if (!/^\d+$/.test(taskId)) return res.status(400).json({ error: 'Invalid Task ID' });

        const url = `${CAPE_API_BASE}/apiv2/tasks/status/${taskId}`;
        console.log('Fetching task status', { taskId, url });

        const response = await axios.get(url);
        try {
            const rawData = response.data?.data;
            const status = typeof rawData === 'string' ? rawData : (rawData?.status || response.data?.status);
            // Update submission status in MongoDB
            if (status) {
                await Submission.findOneAndUpdate(
                    { taskId, userId: req.user.username },
                    { status: status.toLowerCase() }
                );
            }
            await writeLog('tasks.log', { type: 'status_view', ip: req.ip, user: userFromReq(req), taskId, status });
        } catch (error) {
            console.error('Error updating submission status:', error);
        }
        res.json(response.data);
    } catch (error) {
        console.error('Error fetching task status:', error.message);
        await writeLog('tasks.log', { type: 'status_error', ip: req.ip, user: userFromReq(req), taskId: req.params?.taskId, error: error.message });
        res.status(error.response?.status || 500).json({
            error: error.message,
            details: error.response?.data || 'Unknown error'
        });
    }
});

// Visualise: download CAPE JSON report, save as reports/report_<taskId>.json and return visualiser URL
app.get('/api/task/:taskId/visualise', authMiddleware, async (req, res) => {
    try {
        const { taskId } = req.params;
        if (!/^\d+$/.test(taskId)) return res.status(400).json({ error: 'Invalid Task ID' });

        const url = `${CAPE_API_BASE}/apiv2/tasks/get/report/${taskId}`;
        console.log('Fetching report for visualiser', { taskId, url });

        const response = await axios.get(url, { responseType: 'arraybuffer' });

        // Try to determine if this is JSON
        const contentType = (response.headers['content-type'] || '').toLowerCase();
        const isJson = contentType.includes('application/json') || contentType.includes('text/json');

        // Default filename
        const outName = `report_${taskId}.json`;
        const outPath = path.join(REPORTS_DIR, outName);

        // Save file (write buffer)
        try {
            await fsp.writeFile(outPath, response.data);
            await writeLog('tasks.log', { type: 'visualise_saved', ip: req.ip, user: userFromReq(req), taskId, outPath });
        } catch (err) {
            console.error('Error writing report file:', err.message);
            return res.status(500).json({ error: 'Failed to save report file' });
        }

        // If not JSON, still provide the path but warn
        if (!isJson) {
            console.warn('Report content-type not JSON:', contentType);
        }

        // Return the visualiser URL where the visualiser can load the saved JSON
        const visualiserUrl = `/visualiser.html?report=${encodeURIComponent(`/reports/${outName}`)}`;
        return res.json({ visualiserUrl, saved: `/reports/${outName}` });
    } catch (error) {
        console.error('Error preparing visualiser report:', error?.message || error);
        await writeLog('tasks.log', { type: 'visualise_error', ip: req.ip, user: userFromReq(req), taskId: req.params?.taskId, error: error.message });
        return res.status(error.response?.status || 500).json({ error: 'Failed to prepare visualiser report' });
    }
});

// Report download
app.get('/api/task/:taskId/report', authMiddleware, async (req, res) => {
    try {
        const { taskId } = req.params;
        if (!/^\d+$/.test(taskId)) return res.status(400).json({ error: 'Invalid Task ID' });

        const url = `${CAPE_API_BASE}/apiv2/tasks/get/report/${taskId}`;
        const response = await axios.get(url, { responseType: 'arraybuffer' });
        await writeLog('tasks.log', { type: 'report_download', ip: req.ip, user: userFromReq(req), taskId });
        // Forward content-type and suggest filename
        if (response.headers['content-type']) {
            res.set('Content-Type', response.headers['content-type']);
        } else {
            res.set('Content-Type', 'application/octet-stream');
        }
        const disposition = response.headers['content-disposition'] || `attachment; filename="report_${taskId}"`;
        res.set('Content-Disposition', disposition);
        return res.send(response.data);
    } catch (error) {
        await writeLog('tasks.log', { type: 'report_error', ip: req.ip, user: userFromReq(req), taskId: req.params?.taskId, error: error.message });
        return res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// View report (opens full CAPE report page)
app.get('/api/task/:taskId/view', authMiddleware, async (req, res) => {
    try {
        const { taskId } = req.params;
        if (!/^\d+$/.test(taskId)) return res.status(400).json({ error: 'Invalid Task ID' });

        const url = `${CAPE_API_BASE}/apiv2/tasks/view/${taskId}`;
        const response = await axios.get(url);

        await writeLog('tasks.log', { type: 'report_view', ip: req.ip, user: userFromReq(req), taskId });

        // Forward the HTML report directly to the client
        res.set('Content-Type', 'text/html');
        res.send(response.data);
    } catch (error) {
        await writeLog('tasks.log', {
            type: 'report_view_error',
            ip: req.ip,
            user: userFromReq(req),
            taskId: req.params?.taskId,
            error: error.message
        });
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});


// IoCs view
app.get('/api/task/:taskId/iocs', authMiddleware, async (req, res) => {
    try {
        const { taskId } = req.params;
        if (!/^\d+$/.test(taskId)) return res.status(400).json({ error: 'Invalid Task ID' });

        const url = `${CAPE_API_BASE}/apiv2/tasks/get/iocs/${taskId}`;
        const response = await axios.get(url, { responseType: 'json' });
        await writeLog('tasks.log', { type: 'iocs_view', ip: req.ip, user: userFromReq(req), taskId });
        return res.json(response.data);
    } catch (error) {
        await writeLog('tasks.log', { type: 'iocs_error', ip: req.ip, user: userFromReq(req), taskId: req.params?.taskId, error: error.message });
        return res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// Screenshots download (often zip)
app.get('/api/task/:taskId/screenshots', authMiddleware, async (req, res) => {
    try {
        const { taskId } = req.params;
        if (!/^\d+$/.test(taskId)) return res.status(400).json({ error: 'Invalid Task ID' });

        const url = `${CAPE_API_BASE}/apiv2/tasks/get/screenshot/${taskId}`;
        const response = await axios.get(url, { responseType: 'arraybuffer' });
        await writeLog('tasks.log', { type: 'screenshots_download', ip: req.ip, user: userFromReq(req), taskId });
        if (response.headers['content-type']) {
            res.set('Content-Type', response.headers['content-type']);
        } else {
            res.set('Content-Type', 'application/octet-stream');
        }
        const disposition = response.headers['content-disposition'] || `attachment; filename="screenshots_${taskId}.zip"`;
        res.set('Content-Disposition', disposition);
        return res.send(response.data);
    } catch (error) {
        await writeLog('tasks.log', { type: 'screenshots_error', ip: req.ip, user: userFromReq(req), taskId: req.params?.taskId, error: error.message });
        return res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// Malware Bazaar proxy endpoints (embedded so only one server needs to run)
// Health endpoint
app.get('/api/malware-bazaar/health', (req, res) => {
    return res.json({ status: 'ok' });
});

// Proxy endpoint: accepts JSON { hash: '<sha256|md5|sha1>' }
app.post('/api/malware-bazaar', async (req, res) => {
    try {
        const { hash } = req.body;
        if (!hash) return res.status(400).json({ error: 'Missing hash parameter' });
        // Basic hash validation
        if (!/^[a-fA-F0-9]{32,64}$/.test(hash)) return res.status(400).json({ error: 'Invalid hash format' });

        const formData = new FormData();
        formData.append('query', 'get_info');
        formData.append('hash', hash);

        const response = await axios.post(MB_API_URL, formData, {
            headers: {
                'Auth-Key': MB_AUTH_KEY,
                ...formData.getHeaders()
            },
            timeout: 10000
        });

        return res.json(response.data);
    } catch (error) {
        console.error('Malware Bazaar proxy error:', error.message || error);
        const statusCode = error.response?.status || 500;
        const errorBody = error.response?.data || { message: error.message };
        return res.status(statusCode).json({ error: errorBody });
    }
});


// Elasticsearch Integration
const { Client } = require('@elastic/elasticsearch');
const ES_NODE = process.env.ELASTICSEARCH_NODE || 'http://localhost:9200';
const ES_INDEX = process.env.ELASTICSEARCH_INDEX || 'cape-direct-v2';

const ES_USERNAME = process.env.ELASTICSEARCH_USERNAME;
const ES_PASSWORD = process.env.ELASTICSEARCH_PASSWORD;

const esClient = new Client({
    node: ES_NODE,
    auth: {
        username: ES_USERNAME,
        password: ES_PASSWORD
    },
    tls: {
        rejectUnauthorized: false // Self-signed certs are common in local setups
    }
});

// Check ES connection on startup
esClient.ping()
    .then(() => console.log(`Connected to Elasticsearch at ${ES_NODE}`))
    .catch(err => console.error('Elasticsearch connection error:', err.message));

// Get ES Stats
app.get('/api/es/stats', authMiddleware, requireAdmin, async (req, res) => {
    try {
        const count = await esClient.count({ index: ES_INDEX });
        res.json({ count: count.count, index: ES_INDEX });
    } catch (error) {
        console.error('ES Stats Error:', error.message);
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

// List Reports (Search)
app.get('/api/es/reports', authMiddleware, requireAdmin, async (req, res) => {
    try {
        let { q, page = 1, limit = 20 } = req.query;

        // Input validation
        page = parseInt(page);
        limit = parseInt(limit);
        if (isNaN(page) || page < 1) page = 1;
        if (isNaN(limit) || limit < 1) limit = 20;
        if (limit > 100) limit = 100; // Cap limit

        const from = (page - 1) * limit;

        const body = {
            from,
            size: limit,
            sort: [{ "info.id": { order: "desc" } }], // Sort by ID as proxy for time
            query: {
                match_all: {}
            },
            _source: ["target.file.name", "target.file.sha256", "info.score", "info.duration", "info.started", "info.id"], // Fetch necessary fields
            track_total_hits: true
        };

        if (q) {
            // Sanitize q (xss-clean handles basic stuff, but let's be safe)
            const safeQ = String(q).trim();
            if (safeQ) {
                body.query = {
                    multi_match: {
                        query: safeQ,
                        fields: ["target.file.name", "target.file.sha256", "target.file.md5"]
                    }
                };
            }
        }

        const result = await esClient.search({
            index: ES_INDEX,
            body
        });

        const hits = result.hits.hits.map(hit => ({
            id: hit._id,
            ...hit._source
        }));

        res.json({
            total: result.hits.total.value,
            page: page,
            limit: limit,
            data: hits
        });
    } catch (error) {
        console.error('ES Search Error:', error.message);
        res.status(500).json({ error: 'Failed to search reports' });
    }
});

// Get Single Report
app.get('/api/es/reports/:id', authMiddleware, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        // Validate ID format (alphanumeric, dashes, underscores)
        if (!/^[a-zA-Z0-9\-_]+$/.test(id)) return res.status(400).json({ error: 'Invalid Report ID' });

        const result = await esClient.get({
            index: ES_INDEX,
            id
        });
        res.json(result._source);
    } catch (error) {
        console.error('ES Get Error:', error.message);
        if (error.meta && error.meta.statusCode === 404) {
            return res.status(404).json({ error: 'Report not found' });
        }
        res.status(500).json({ error: 'Failed to fetch report' });
    }
});

// --- ADMIN USER STATS ENDPOINTS ---

// Get all users with stats
app.get('/api/admin/users', authMiddleware, requireAdmin, async (req, res) => {
    try {
        // Aggregate Login History
        // We want: username, role, lastLogin, totalLogins, totalSubmissions

        // 1. Get all users from User collection (students)
        // Admin user might not be in User collection if not using DB, so we handle that.

        const users = await User.find().lean();

        // 2. Get stats for each user (and any others found in LoginHistory/Submission)
        // Aggregation is more efficient

        const loginStats = await LoginHistory.aggregate([
            { $group: { _id: "$username", count: { $sum: 1 }, lastLogin: { $max: "$timestamp" } } }
        ]);

        const submissionStats = await Submission.aggregate([
            { $group: { _id: "$userId", count: { $sum: 1 }, lastSubmission: { $max: "$timestamp" } } }
        ]);

        // Merge data
        const userMap = {};

        // Initialize with known users
        users.forEach(u => {
            userMap[u.username] = {
                username: u.username,
                role: u.role,
                joinedAt: u.createdAt,
                lastLogin: u.lastLogin, // From User model
                totalLogins: 0,
                totalSubmissions: 0,
                lastSubmission: null
            };
        });

        // Merge Login Stats
        loginStats.forEach(stat => {
            if (!userMap[stat._id]) {
                userMap[stat._id] = {
                    username: stat._id,
                    role: 'unknown',
                    joinedAt: null,
                    lastLogin: null,
                    totalLogins: 0,
                    totalSubmissions: 0,
                    lastSubmission: null
                };
            }
            userMap[stat._id].totalLogins = stat.count;
            // Prefer the history timestamp if newer
            if (!userMap[stat._id].lastLogin || stat.lastLogin > userMap[stat._id].lastLogin) {
                userMap[stat._id].lastLogin = stat.lastLogin;
            }
            if (userMap[stat._id].role === 'unknown' && stat._id === ADMIN_USERNAME) {
                userMap[stat._id].role = 'admin';
            }
        });

        // Merge Submission Stats
        submissionStats.forEach(stat => {
            if (!userMap[stat._id]) {
                // Should exist if they logged in, but just in case
                userMap[stat._id] = {
                    username: stat._id,
                    role: 'unknown',
                    joinedAt: null,
                    lastLogin: null,
                    totalLogins: 0,
                    totalSubmissions: 0,
                    lastSubmission: null
                };
            }
            userMap[stat._id].totalSubmissions = stat.count;
            userMap[stat._id].lastSubmission = stat.lastSubmission;
        });

        const result = Object.values(userMap).sort((a, b) => {
            // Sort by last login desc, then username
            const timeA = new Date(a.lastLogin || 0).getTime();
            const timeB = new Date(b.lastLogin || 0).getTime();
            return timeB - timeA;
        });

        res.json(result);

    } catch (error) {
        console.error('Error fetching user stats:', error);
        res.status(500).json({ error: 'Failed to fetch user stats' });
    }
});

// Get details for a specific user
app.get('/api/admin/users/:username', authMiddleware, requireAdmin, async (req, res) => {
    try {
        const { username } = req.params;

        // Parallel fetch
        const [user, logins, submissions] = await Promise.all([
            User.findOne({ username }).lean(),
            LoginHistory.find({ username }).sort({ timestamp: -1 }).limit(50).lean(),
            Submission.find({ userId: username }).sort({ timestamp: -1 }).limit(50).lean()
        ]);

        // Refresh status of non-terminal submissions from CAPE API
        const terminalStatuses = ['reported', 'completed', 'success', 'error', 'failed', 'timedout'];
        const pendingSubs = submissions.filter(s =>
            s.taskId && !terminalStatuses.includes((s.status || '').toLowerCase())
        );

        if (pendingSubs.length > 0) {
            await Promise.allSettled(
                pendingSubs.map(async (sub) => {
                    try {
                        const url = `${CAPE_API_BASE}/apiv2/tasks/status/${sub.taskId}`;
                        const response = await axios.get(url, { timeout: 5000 });
                        const rawData = response.data?.data;
                        const status = typeof rawData === 'string' ? rawData : (rawData?.status || response.data?.status);
                        if (status) {
                            const lowerStatus = status.toLowerCase();
                            await Submission.findOneAndUpdate(
                                { taskId: sub.taskId },
                                { status: lowerStatus }
                            );
                            sub.status = lowerStatus; // update the response object too
                        }
                    } catch (_) {
                        // Ignore individual CAPE API failures
                    }
                })
            );
        }

        res.json({
            user: user || { username, role: 'unknown' },
            loginHistory: logins,
            submissions: submissions
        });

    } catch (error) {
        console.error('Error fetching user details:', error);
        res.status(500).json({ error: 'Failed to fetch user details' });
    }
});

// Lookup submission by Task ID (returns username)
app.get('/api/admin/submission-lookup/:taskId', authMiddleware, requireAdmin, async (req, res) => {
    try {
        const { taskId } = req.params;
        if (!taskId || !taskId.trim()) return res.status(400).json({ error: 'Task ID required' });

        const submission = await Submission.findOne({ taskId: taskId.trim() }).lean();
        if (!submission) return res.status(404).json({ error: 'No submission found for this Task ID' });

        res.json({
            taskId: submission.taskId,
            username: submission.userId,
            filename: submission.filename,
            status: submission.status,
            timestamp: submission.timestamp
        });
    } catch (error) {
        console.error('Error looking up submission:', error);
        res.status(500).json({ error: 'Failed to look up submission' });
    }
});

// Get restriction status
app.get('/api/admin/restriction-status', authMiddleware, requireAdmin, (req, res) => {
    res.json({ enabled: submissionRestrictionEnabled });
});

// Toggle restriction
app.post('/api/admin/toggle-restriction', authMiddleware, requireAdmin, (req, res) => {
    submissionRestrictionEnabled = !submissionRestrictionEnabled;
    res.json({ enabled: submissionRestrictionEnabled });
});

// Dashboard Stats Endpoint
app.get('/api/admin/dashboard-stats', authMiddleware, requireAdmin, async (req, res) => {
    try {
        // Support optional ?date=YYYY-MM-DD query parameter
        let startOfDay, endOfDay, dateLabel;
        if (req.query.date) {
            const parsed = new Date(req.query.date + 'T00:00:00');
            if (isNaN(parsed.getTime())) {
                return res.status(400).json({ error: 'Invalid date format. Use YYYY-MM-DD.' });
            }
            startOfDay = parsed;
            endOfDay = new Date(parsed);
            endOfDay.setDate(endOfDay.getDate() + 1);
            dateLabel = req.query.date;
        } else {
            const now = new Date();
            startOfDay = new Date(now.getFullYear(), now.getMonth(), now.getDate());
            endOfDay = new Date(startOfDay);
            endOfDay.setDate(endOfDay.getDate() + 1);
            dateLabel = 'today';
        }

        // 1. Summary Counts
        const totalUsers = await User.countDocuments();
        const totalSubmissions = await Submission.countDocuments();
        const loginsOnDate = await LoginHistory.countDocuments({ timestamp: { $gte: startOfDay, $lt: endOfDay } });
        const submissionsOnDate = await Submission.countDocuments({ timestamp: { $gte: startOfDay, $lt: endOfDay } });

        // 2. Timeline (Last 30 Days)
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

        const loginTimeline = await LoginHistory.aggregate([
            { $match: { timestamp: { $gte: thirtyDaysAgo } } },
            {
                $group: {
                    _id: { $dateToString: { format: "%Y-%m-%d", date: "$timestamp" } },
                    count: { $sum: 1 }
                }
            },
            { $sort: { _id: 1 } }
        ]);

        const submissionTimeline = await Submission.aggregate([
            { $match: { timestamp: { $gte: thirtyDaysAgo } } },
            {
                $group: {
                    _id: { $dateToString: { format: "%Y-%m-%d", date: "$timestamp" } },
                    count: { $sum: 1 }
                }
            },
            { $sort: { _id: 1 } }
        ]);

        // 3. File Type Distribution
        const fileTypes = await Submission.aggregate([
            { $group: { _id: "$package", count: { $sum: 1 } } },
            { $sort: { count: -1 } }
        ]);

        // 4. Top Users (by submission)
        const topUsers = await Submission.aggregate([
            { $group: { _id: "$userId", count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $limit: 5 }
        ]);

        res.json({
            summary: {
                totalUsers,
                totalSubmissions,
                loginsOnDate,
                submissionsOnDate,
                dateLabel
            },
            timeline: {
                logins: loginTimeline,
                submissions: submissionTimeline
            },
            fileTypes,
            topUsers
        });

    } catch (error) {
        console.error('Error fetching dashboard stats:', error);
        res.status(500).json({ error: 'Failed to fetch dashboard stats' });
    }
});

// --- IP Geolocation Proxy ---
// Proxies geolocation lookups through the server so they work even when
// the university network blocks direct browser requests to third-party APIs.
const geoLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300, // generous limit for geo lookups
    message: { error: 'Too many geolocation requests' }
});
app.get('/api/geoip/:ip', geoLimiter, async (req, res) => {
    const ip = req.params.ip;
    // Basic IPv4/IPv6 validation
    if (!/^[\d.:a-fA-F]+$/.test(ip)) return res.status(400).json({ error: 'Invalid IP' });

    const apis = [
        {
            url: `https://ipapi.co/${ip}/json/`,
            parse: d => ({
                city: d.city, region: d.region, country: d.country_name,
                lat: d.latitude, lon: d.longitude
            })
        },
        {
            url: `https://ipwhois.app/json/${ip}`,
            parse: d => ({
                city: d.city, region: d.region, country: d.country,
                lat: d.latitude, lon: d.longitude
            })
        },
        {
            url: `https://ipapi.com/ip_api.php?ip=${ip}`,
            parse: d => ({
                city: d.city, region: d.regionName || d.region, country: d.countryName || d.country_name,
                lat: d.latitude || d.lat, lon: d.longitude || d.lon
            })
        },
        {
            url: `https://json.geoiplookup.io/${ip}`,
            parse: d => ({
                city: d.city, region: d.region, country: d.country_name,
                lat: d.latitude, lon: d.longitude
            })
        },
        {
            url: `https://api.ip.sb/geoip/${ip}`,
            parse: d => ({
                city: d.city, region: d.region, country: d.country,
                lat: d.latitude, lon: d.longitude
            })
        }
    ];

    for (const api of apis) {
        try {
            const response = await axios.get(api.url, { timeout: 5000 });
            const parsed = api.parse(response.data);
            if (parsed.city || parsed.country) {
                const location = `${parsed.city || 'Unknown'}, ${parsed.region || 'Unknown'}, ${parsed.country || 'Unknown'}`;
                return res.json({
                    ip,
                    location,
                    city: parsed.city || 'Unknown',
                    region: parsed.region || 'Unknown',
                    country: parsed.country || 'Unknown',
                    lat: parsed.lat ? parseFloat(parsed.lat) : null,
                    lon: parsed.lon ? parseFloat(parsed.lon) : null
                });
            }
        } catch (e) {
            // try next API
            continue;
        }
    }
    // All APIs failed
    return res.status(502).json({ error: 'All geolocation APIs failed', ip });
});

const HOST = process.env.HOST || '0.0.0.0';
app.listen(PORT, HOST, () => {
    console.log(`Server running on http://${HOST}:${PORT}`);
    console.log(`Access the CAPE upload interface at http://${HOST}:${PORT}`);
});

