// require('dotenv').config();
// const express = require('express');
// const cors = require('cors');
// const rateLimit = require('express-rate-limit');
// const multer = require('multer');
// const FormData = require('form-data');
// const axios = require('axios');
// // Malware Bazaar proxy config
// const MB_AUTH_KEY = process.env.MB_AUTH_KEY || 'c142633e2abd97535582df9842fbfbbfcb7298e243d2a4ad';
// const MB_API_URL = process.env.MB_API_URL || 'https://mb-api.abuse.ch/api/v1/';
// const mongoose = require('mongoose');
// const argon2 = require('argon2');
// const jwt = require('jsonwebtoken');
// const path = require('path');
// const fs = require('fs');
// const fsp = require('fs/promises');

// const helmet = require('helmet');
// const mongoSanitize = require('express-mongo-sanitize');
// const hpp = require('hpp');
// const xss = require('xss-clean');

// const app = express();

// // Global state for submission restriction
// let submissionRestrictionEnabled = true;

// // Security Headers
// app.use(helmet({
//     contentSecurityPolicy: false, // Disable CSP for simplicity in this dev setup, or configure strictly
// }));

// // Prevent Parameter Pollution
// app.use(hpp());

// // Data Sanitization against NoSQL Query Injection
// app.use(mongoSanitize());

// // Data Sanitization against XSS
// app.use(xss());

// app.use(cors());
// app.use(express.json({ limit: '10kb' })); // Limit body size
// app.use(express.urlencoded({ extended: true }));

// // Global Request Logger to server.log
// app.use(async (req, res, next) => {
//     const start = Date.now();
//     res.on('finish', async () => {
//         const duration = Date.now() - start;
//         await writeLog('../logs/server_activity.log', {
//             type: 'request',
//             method: req.method,
//             url: req.originalUrl,
//             status: res.statusCode,
//             ip: req.ip,
//             duration: `${duration}ms`
//         });
//     });
//     next();
// });

// // Basic rate limiting
// const limiter = rateLimit({
//     windowMs: 15 * 60 * 1000, // 15 minutes
//     max: 100, // Limit each IP to 100 requests per windowMs
//     message: 'Too many requests from this IP, please try again later'
// });
// app.use(limiter);

// const upload = multer({
//     storage: multer.memoryStorage(),
//     limits: { fileSize: 50 * 1024 * 1024 } // 50MB limit
// });
// const PORT = process.env.PORT || 3000;

// // CAPE API endpoints
// const CAPE_API_BASE = process.env.CAPE_API_BASE || 'http://10.20.8.79:8000';
// const CAPE_API_UPLOAD_URL = `${CAPE_API_BASE}/apiv2/tasks/create/file/`;

// // Logging helpers (JSONL files in ./logs)
// const LOG_DIR = path.join(__dirname, 'logs');
// function ensureLogDir() {
//     try { if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true }); } catch (_) { }
// }
// ensureLogDir();

// // Reports directory for visualiser input files
// const REPORTS_DIR = path.join(__dirname, 'reports');
// function ensureReportsDir() {
//     try { if (!fs.existsSync(REPORTS_DIR)) fs.mkdirSync(REPORTS_DIR, { recursive: true }); } catch (_) { }
// }
// ensureReportsDir();

// async function writeLog(fileName, record) {
//     const line = JSON.stringify({ ts: new Date().toISOString(), ...record }) + '\n';
//     try { await fsp.appendFile(path.join(LOG_DIR, fileName), line, 'utf8'); } catch (e) { console.error('Log write error:', e.message); }
// }

// function userFromReq(req) {
//     return req.user?.username || 'anonymous';
// }

// // MongoDB connection
// const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/cape';
// mongoose.connect(MONGODB_URI)
//     .then(() => console.log('MongoDB connected'))
//     .catch(err => console.error('MongoDB connection error:', err.message));

// // Submission model for storing history
// const submissionSchema = new mongoose.Schema({
//     taskId: { type: String, required: true },
//     filename: { type: String, required: true },
//     timestamp: { type: Date, default: Date.now },
//     status: { type: String, default: 'pending' },
//     userId: { type: String, required: true }, // username of the user who submitted
//     package: { type: String, default: 'exe' },
//     timeout: { type: Number, default: 300 },
//     priority: { type: Number, default: 1 },
//     size: Number,
//     mimetype: String
// });

// const Submission = mongoose.model('Submission', submissionSchema);

// // JWT helpers
// const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
// function signTokens(user) {
//     const accessToken = jwt.sign({ sub: user.sub, role: user.role, username: user.username }, JWT_SECRET, { expiresIn: '12h' });
//     return { accessToken };
// }

// function authMiddleware(req, res, next) {
//     const header = req.headers['authorization'] || '';
//     const token = header.startsWith('Bearer ') ? header.slice(7) : null;
//     if (!token) return res.status(401).json({ error: 'Missing token' });
//     try {
//         const payload = jwt.verify(token, JWT_SECRET);
//         req.user = payload;
//         return next();
//     } catch (e) {
//         return res.status(401).json({ error: 'Invalid or expired token' });
//     }
// }

// // User model for storing login history
// const userSchema = new mongoose.Schema({
//     username: { type: String, required: true, unique: true }, // Roll number for students
//     email: { type: String, unique: true, sparse: true }, // Optional email (unique index exists)
//     role: { type: String, default: 'student' },
//     createdAt: { type: Date, default: Date.now },
//     lastLogin: { type: Date, default: Date.now }
// });

// const User = mongoose.model('User', userSchema);



// // Login History Model
// const loginHistorySchema = new mongoose.Schema({
//     username: { type: String, required: true, index: true },
//     role: { type: String, required: true },
//     ip: String,
//     timestamp: { type: Date, default: Date.now },
//     userAgent: String
// });
// const LoginHistory = mongoose.model('LoginHistory', loginHistorySchema);

// // Auth routes (fixed credential)
// const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'root';
// const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || null; // plaintext fallback
// const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || null; // argon2 hash optional
// const STUDENT_PASSWORD = process.env.STUDENT_PASSWORD || 'student123';

// function requireAdmin(req, res, next) {
//     if (req.user && req.user.role === 'admin') {
//         return next();
//     }
//     return res.status(403).json({ error: 'Access denied: Admins only' });
// }

// app.post('/api/auth/login', async (req, res) => {
//     try {
//         const { username, password } = req.body;
//         console.log('Login attempt:', { username }); // Don't log passwords
//         if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

//         // Basic brute force protection (sleep)
//         await new Promise(r => setTimeout(r, 500));

//         let role = 'user';
//         let isAuthenticated = false;

//         // Check for Student Login (10-digit roll number)
//         if (/^\d{10}$/.test(username)) {
//             if (password === STUDENT_PASSWORD) {
//                 role = 'student';
//                 isAuthenticated = true;

//                 // Persist student to MongoDB
//                 try {
//                     await User.findOneAndUpdate(
//                         { username },
//                         {
//                             $setOnInsert: {
//                                 username,
//                                 role: 'student',
//                                 createdAt: new Date(),
//                                 email: `${username}@student.local` // Generate unique email to satisfy unique index
//                             },
//                             $set: { lastLogin: new Date() }
//                         },
//                         { upsert: true, new: true }
//                     );
//                 } catch (dbErr) {
//                     console.error('Error saving user to DB:', dbErr.message);
//                     // Don't block login if DB write fails, but log it
//                 }

//                 await writeLog('auth.log', { type: 'login_success', ip: req.ip, username, role });
//             }
//         }
//         // Check for Admin Login
//         else if (username === ADMIN_USERNAME) {
//             if (ADMIN_PASSWORD_HASH) {
//                 try {
//                     isAuthenticated = await argon2.verify(ADMIN_PASSWORD_HASH, password);
//                 } catch (_) { isAuthenticated = false; }
//             } else if (ADMIN_PASSWORD) {
//                 isAuthenticated = password === ADMIN_PASSWORD;
//             }
//             if (isAuthenticated) {
//                 role = 'admin';
//                 await writeLog('auth.log', { type: 'login_success', ip: req.ip, username, role });
//             }
//         }

//         if (isAuthenticated) {
//             // Record Login History
//             try {
//                 await LoginHistory.create({
//                     username,
//                     role,
//                     ip: req.ip,
//                     userAgent: req.headers['user-agent']
//                 });
//             } catch (histErr) {
//                 console.error('Error saving login history:', histErr.message);
//             }
//         }

//         if (!isAuthenticated) {
//             await writeLog('auth.log', { type: 'login_failed', ip: req.ip, username });
//             return res.status(401).json({ error: 'Invalid credentials' });
//         }

//         const tokens = signTokens({ sub: username, role, username });
//         return res.json({ user: { username, role }, ...tokens });
//     } catch (err) {
//         console.error('Login error:', err.message);
//         await writeLog('auth.log', { type: 'login_error', ip: req.ip, error: err.message });
//         return res.status(500).json({ error: 'Login failed' });
//     }
// });

// // Serve static files (index.html)
// app.use(express.static(__dirname));

// // List submissions for the current user
// app.get('/api/submissions', authMiddleware, async (req, res) => {
//     try {
//         const submissions = await Submission.find({ userId: req.user.username })
//             .sort({ timestamp: -1 })
//             .limit(100); // Optional limit
//         res.json(submissions);
//     } catch (error) {
//         console.error('Error fetching submissions:', error);
//         res.status(500).json({ error: 'Failed to fetch submission history' });
//     }
// });

// // Bulk-refresh statuses of non-terminal submissions from CAPE API
// app.post('/api/submissions/refresh', authMiddleware, async (req, res) => {
//     try {
//         const submissions = await Submission.find({ userId: req.user.username })
//             .sort({ timestamp: -1 })
//             .limit(100)
//             .lean();

//         const terminalStatuses = ['reported', 'completed', 'success', 'error', 'failed', 'timedout'];
//         const pendingSubs = submissions.filter(s =>
//             s.taskId && !terminalStatuses.includes((s.status || '').toLowerCase())
//         );

//         let updated = 0;
//         if (pendingSubs.length > 0) {
//             const results = await Promise.allSettled(
//                 pendingSubs.map(async (sub) => {
//                     try {
//                         const url = `${CAPE_API_BASE}/apiv2/tasks/status/${sub.taskId}`;
//                         const response = await axios.get(url, { timeout: 5000 });
//                         const rawData = response.data?.data;
//                         const status = typeof rawData === 'string' ? rawData : (rawData?.status || response.data?.status);
//                         if (status) {
//                             const lowerStatus = status.toLowerCase();
//                             if (lowerStatus !== (sub.status || '').toLowerCase()) {
//                                 await Submission.findOneAndUpdate(
//                                     { taskId: sub.taskId, userId: req.user.username },
//                                     { status: lowerStatus }
//                                 );
//                                 updated++;
//                             }
//                         }
//                     } catch (_) {
//                         // Ignore individual CAPE API failures
//                     }
//                 })
//             );
//         }

//         // Return the refreshed submissions
//         const refreshed = await Submission.find({ userId: req.user.username })
//             .sort({ timestamp: -1 })
//             .limit(100);
//         res.json({ updated, submissions: refreshed });
//     } catch (error) {
//         console.error('Error refreshing submission statuses:', error);
//         res.status(500).json({ error: 'Failed to refresh statuses' });
//     }
// });

// // Update submission status
// app.put('/api/submissions/:taskId', authMiddleware, async (req, res) => {
//     try {
//         const { taskId } = req.params;
//         const { status } = req.body;
//         if (!status) return res.status(400).json({ error: 'Status required' });

//         const submission = await Submission.findOneAndUpdate(
//             { taskId, userId: req.user.username },
//             { status },
//             { new: true }
//         );

//         if (!submission) return res.status(404).json({ error: 'Submission not found' });
//         res.json(submission);
//     } catch (error) {
//         console.error('Error updating submission:', error);
//         res.status(500).json({ error: 'Failed to update submission' });
//     }
// });

// // Delete a submission
// app.delete('/api/submissions/:taskId', authMiddleware, async (req, res) => {
//     try {
//         const { taskId } = req.params;
//         const result = await Submission.findOneAndDelete({ taskId, userId: req.user.username });
//         if (!result) return res.status(404).json({ error: 'Submission not found' });
//         res.json({ success: true });
//     } catch (error) {
//         console.error('Error deleting submission:', error);
//         res.status(500).json({ error: 'Failed to delete submission' });
//     }
// });

// // Handle file upload to CAPE API (protected)
// app.post('/api/upload', authMiddleware, upload.single('file'), async (req, res) => {
//     try {
//         const file = req.file;
//         const { package: packageType, timeout, priority } = req.body;

//         if (!file) {
//             await writeLog('tasks.log', { type: 'submit_missing_file', ip: req.ip, user: userFromReq(req) });
//             return res.status(400).json({ error: 'No file provided' });
//         }

//         // Validate inputs
//         const validPackages = ['exe', 'dll', 'zip', 'apk', 'office', 'pdf', 'browser', 'chrome', 'firefox', 'ie', 'auto'];
//         const pkg = (packageType && validPackages.includes(packageType)) ? packageType : 'exe';
//         const tm = Math.min(Math.max(parseInt(timeout) || 300, 100), 300); // 100s to 300s
//         // Only admin users can set custom priority; students are forced to 1
//         const prio = (req.user && (req.user.role === 'admin' || req.user.role === 'root'))
//             ? Math.min(Math.max(parseInt(priority) || 1, 1), 5)
//             : 1;

//         // Rate limit check
//         if (submissionRestrictionEnabled && req.user && req.user.role !== 'admin' && req.user.role !== 'root') {
//             const fiveHoursAgo = new Date(Date.now() - 5 * 60 * 60 * 1000);
//             const recentSubmissionsCount = await Submission.countDocuments({
//                 userId: req.user.username,
//                 timestamp: { $gte: fiveHoursAgo }
//             });
//             if (recentSubmissionsCount >= 5) {
//                 await writeLog('tasks.log', { type: 'submit_rate_limited', ip: req.ip, user: userFromReq(req) });
//                 return res.status(429).json({ error: 'Submission limit reached. Max 5 submissions per 5 hours.' });
//             }
//         }

//         // Create form data to forward to CAPE API
//         const formData = new FormData();
//         formData.append('file', file.buffer, {
//             filename: file.originalname,
//             contentType: file.mimetype
//         });
//         formData.append('package', pkg);
//         formData.append('timeout', String(tm));
//         formData.append('priority', String(prio));

//         await writeLog('tasks.log', {
//             type: 'submit_attempt', ip: req.ip, user: userFromReq(req),
//             filename: file.originalname, size: file.size, mimetype: file.mimetype,
//             package: pkg, timeout: tm, priority: prio
//         });

//         // Forward request to CAPE API
//         const response = await axios.post(CAPE_API_UPLOAD_URL, formData, {
//             headers: {
//                 ...formData.getHeaders()
//             },
//             maxContentLength: Infinity,
//             maxBodyLength: Infinity
//         });

//         // Log the response for debugging
//         console.log('CAPE API Upload Response:', JSON.stringify(response.data, null, 2));
//         try {
//             const taskIds = response.data?.data?.task_ids || response.data?.task_ids || [];
//             const taskId = taskIds[0]; // Assuming single file upload

//             // Save submission to MongoDB
//             if (taskId) {
//                 const submission = new Submission({
//                     taskId,
//                     filename: file.originalname,
//                     userId: req.user.username,
//                     package: pkg,
//                     timeout: tm,
//                     priority: prio,
//                     size: file.size,
//                     mimetype: file.mimetype,
//                     status: 'pending'
//                 });
//                 await submission.save();
//             }

//             await writeLog('tasks.log', { type: 'submit_success', ip: req.ip, user: userFromReq(req), filename: file.originalname, taskIds });
//         } catch (error) {
//             console.error('Error saving submission:', error);
//         }

//         res.json(response.data);
//     } catch (error) {
//         console.error('Error uploading to CAPE API:', error.message);
//         await writeLog('tasks.log', { type: 'submit_error', ip: req.ip, user: userFromReq(req), error: error.message, details: error.response?.data });
//         res.status(error.response?.status || 500).json({
//             error: error.message,
//             details: error.response?.data || 'Unknown error'
//         });
//     }
// });

// // Handle task status lookup (protected)
// app.get('/api/task/:taskId', authMiddleware, async (req, res) => {
//     try {
//         const { taskId } = req.params;
//         if (!/^\d+$/.test(taskId)) return res.status(400).json({ error: 'Invalid Task ID' });

//         const url = `${CAPE_API_BASE}/apiv2/tasks/status/${taskId}`;
//         console.log('Fetching task status', { taskId, url });

//         const response = await axios.get(url);
//         try {
//             const rawData = response.data?.data;
//             const status = typeof rawData === 'string' ? rawData : (rawData?.status || response.data?.status);
//             // Update submission status in MongoDB
//             if (status) {
//                 await Submission.findOneAndUpdate(
//                     { taskId, userId: req.user.username },
//                     { status: status.toLowerCase() }
//                 );
//             }
//             await writeLog('tasks.log', { type: 'status_view', ip: req.ip, user: userFromReq(req), taskId, status });
//         } catch (error) {
//             console.error('Error updating submission status:', error);
//         }
//         res.json(response.data);
//     } catch (error) {
//         console.error('Error fetching task status:', error.message);
//         await writeLog('tasks.log', { type: 'status_error', ip: req.ip, user: userFromReq(req), taskId: req.params?.taskId, error: error.message });
//         res.status(error.response?.status || 500).json({
//             error: error.message,
//             details: error.response?.data || 'Unknown error'
//         });
//     }
// });

// // Visualise: download CAPE JSON report, save as reports/report_<taskId>.json and return visualiser URL
// app.get('/api/task/:taskId/visualise', authMiddleware, async (req, res) => {
//     try {
//         const { taskId } = req.params;
//         if (!/^\d+$/.test(taskId)) return res.status(400).json({ error: 'Invalid Task ID' });

//         const url = `${CAPE_API_BASE}/apiv2/tasks/get/report/${taskId}`;
//         console.log('Fetching report for visualiser', { taskId, url });

//         const response = await axios.get(url, { responseType: 'arraybuffer' });

//         // Try to determine if this is JSON
//         const contentType = (response.headers['content-type'] || '').toLowerCase();
//         const isJson = contentType.includes('application/json') || contentType.includes('text/json');

//         // Default filename
//         const outName = `report_${taskId}.json`;
//         const outPath = path.join(REPORTS_DIR, outName);

//         // Save file (write buffer)
//         try {
//             await fsp.writeFile(outPath, response.data);
//             await writeLog('tasks.log', { type: 'visualise_saved', ip: req.ip, user: userFromReq(req), taskId, outPath });
//         } catch (err) {
//             console.error('Error writing report file:', err.message);
//             return res.status(500).json({ error: 'Failed to save report file' });
//         }

//         // If not JSON, still provide the path but warn
//         if (!isJson) {
//             console.warn('Report content-type not JSON:', contentType);
//         }

//         // Return the visualiser URL where the visualiser can load the saved JSON
//         const visualiserUrl = `/visualiser.html?report=${encodeURIComponent(`/reports/${outName}`)}`;
//         return res.json({ visualiserUrl, saved: `/reports/${outName}` });
//     } catch (error) {
//         console.error('Error preparing visualiser report:', error?.message || error);
//         await writeLog('tasks.log', { type: 'visualise_error', ip: req.ip, user: userFromReq(req), taskId: req.params?.taskId, error: error.message });
//         return res.status(error.response?.status || 500).json({ error: 'Failed to prepare visualiser report' });
//     }
// });

// // Report download
// app.get('/api/task/:taskId/report', authMiddleware, async (req, res) => {
//     try {
//         const { taskId } = req.params;
//         if (!/^\d+$/.test(taskId)) return res.status(400).json({ error: 'Invalid Task ID' });

//         const url = `${CAPE_API_BASE}/apiv2/tasks/get/report/${taskId}`;
//         const response = await axios.get(url, { responseType: 'arraybuffer' });
//         await writeLog('tasks.log', { type: 'report_download', ip: req.ip, user: userFromReq(req), taskId });
//         // Forward content-type and suggest filename
//         if (response.headers['content-type']) {
//             res.set('Content-Type', response.headers['content-type']);
//         } else {
//             res.set('Content-Type', 'application/octet-stream');
//         }
//         const disposition = response.headers['content-disposition'] || `attachment; filename="report_${taskId}"`;
//         res.set('Content-Disposition', disposition);
//         return res.send(response.data);
//     } catch (error) {
//         await writeLog('tasks.log', { type: 'report_error', ip: req.ip, user: userFromReq(req), taskId: req.params?.taskId, error: error.message });
//         return res.status(error.response?.status || 500).json({ error: error.message });
//     }
// });

// // View report (opens full CAPE report page)
// app.get('/api/task/:taskId/view', authMiddleware, async (req, res) => {
//     try {
//         const { taskId } = req.params;
//         if (!/^\d+$/.test(taskId)) return res.status(400).json({ error: 'Invalid Task ID' });

//         const url = `${CAPE_API_BASE}/apiv2/tasks/view/${taskId}`;
//         const response = await axios.get(url);

//         await writeLog('tasks.log', { type: 'report_view', ip: req.ip, user: userFromReq(req), taskId });

//         // Forward the HTML report directly to the client
//         res.set('Content-Type', 'text/html');
//         res.send(response.data);
//     } catch (error) {
//         await writeLog('tasks.log', {
//             type: 'report_view_error',
//             ip: req.ip,
//             user: userFromReq(req),
//             taskId: req.params?.taskId,
//             error: error.message
//         });
//         res.status(error.response?.status || 500).json({ error: error.message });
//     }
// });


// // IoCs view
// app.get('/api/task/:taskId/iocs', authMiddleware, async (req, res) => {
//     try {
//         const { taskId } = req.params;
//         if (!/^\d+$/.test(taskId)) return res.status(400).json({ error: 'Invalid Task ID' });

//         const url = `${CAPE_API_BASE}/apiv2/tasks/get/iocs/${taskId}`;
//         const response = await axios.get(url, { responseType: 'json' });
//         await writeLog('tasks.log', { type: 'iocs_view', ip: req.ip, user: userFromReq(req), taskId });
//         return res.json(response.data);
//     } catch (error) {
//         await writeLog('tasks.log', { type: 'iocs_error', ip: req.ip, user: userFromReq(req), taskId: req.params?.taskId, error: error.message });
//         return res.status(error.response?.status || 500).json({ error: error.message });
//     }
// });

// // Screenshots download (often zip)
// app.get('/api/task/:taskId/screenshots', authMiddleware, async (req, res) => {
//     try {
//         const { taskId } = req.params;
//         if (!/^\d+$/.test(taskId)) return res.status(400).json({ error: 'Invalid Task ID' });

//         const url = `${CAPE_API_BASE}/apiv2/tasks/get/screenshot/${taskId}`;
//         const response = await axios.get(url, { responseType: 'arraybuffer' });
//         await writeLog('tasks.log', { type: 'screenshots_download', ip: req.ip, user: userFromReq(req), taskId });
//         if (response.headers['content-type']) {
//             res.set('Content-Type', response.headers['content-type']);
//         } else {
//             res.set('Content-Type', 'application/octet-stream');
//         }
//         const disposition = response.headers['content-disposition'] || `attachment; filename="screenshots_${taskId}.zip"`;
//         res.set('Content-Disposition', disposition);
//         return res.send(response.data);
//     } catch (error) {
//         await writeLog('tasks.log', { type: 'screenshots_error', ip: req.ip, user: userFromReq(req), taskId: req.params?.taskId, error: error.message });
//         return res.status(error.response?.status || 500).json({ error: error.message });
//     }
// });

// // Malware Bazaar proxy endpoints (embedded so only one server needs to run)
// // Health endpoint
// app.get('/api/malware-bazaar/health', (req, res) => {
//     return res.json({ status: 'ok' });
// });

// // Proxy endpoint: accepts JSON { hash: '<sha256|md5|sha1>' }
// app.post('/api/malware-bazaar', async (req, res) => {
//     try {
//         const { hash } = req.body;
//         if (!hash) return res.status(400).json({ error: 'Missing hash parameter' });
//         // Basic hash validation
//         if (!/^[a-fA-F0-9]{32,64}$/.test(hash)) return res.status(400).json({ error: 'Invalid hash format' });

//         const formData = new FormData();
//         formData.append('query', 'get_info');
//         formData.append('hash', hash);

//         const response = await axios.post(MB_API_URL, formData, {
//             headers: {
//                 'Auth-Key': MB_AUTH_KEY,
//                 ...formData.getHeaders()
//             },
//             timeout: 10000
//         });

//         return res.json(response.data);
//     } catch (error) {
//         console.error('Malware Bazaar proxy error:', error.message || error);
//         const statusCode = error.response?.status || 500;
//         const errorBody = error.response?.data || { message: error.message };
//         return res.status(statusCode).json({ error: errorBody });
//     }
// });


// // Elasticsearch Integration
// const { Client } = require('@elastic/elasticsearch');
// const ES_NODE = process.env.ELASTICSEARCH_NODE || 'http://localhost:9200';
// const ES_INDEX = process.env.ELASTICSEARCH_INDEX || 'cape-direct-v2';

// const ES_USERNAME = process.env.ELASTICSEARCH_USERNAME;
// const ES_PASSWORD = process.env.ELASTICSEARCH_PASSWORD;

// const esClient = new Client({
//     node: ES_NODE,
//     auth: {
//         username: ES_USERNAME,
//         password: ES_PASSWORD
//     },
//     tls: {
//         rejectUnauthorized: false // Self-signed certs are common in local setups
//     }
// });

// // Check ES connection on startup
// esClient.ping()
//     .then(() => console.log(`Connected to Elasticsearch at ${ES_NODE}`))
//     .catch(err => console.error('Elasticsearch connection error:', err.message));

// // Get ES Stats
// app.get('/api/es/stats', authMiddleware, requireAdmin, async (req, res) => {
//     try {
//         const count = await esClient.count({ index: ES_INDEX });
//         res.json({ count: count.count, index: ES_INDEX });
//     } catch (error) {
//         console.error('ES Stats Error:', error.message);
//         res.status(500).json({ error: 'Failed to fetch stats' });
//     }
// });

// // List Reports (Search)
// app.get('/api/es/reports', authMiddleware, requireAdmin, async (req, res) => {
//     try {
//         let { q, page = 1, limit = 20 } = req.query;

//         // Input validation
//         page = parseInt(page);
//         limit = parseInt(limit);
//         if (isNaN(page) || page < 1) page = 1;
//         if (isNaN(limit) || limit < 1) limit = 20;
//         if (limit > 100) limit = 100; // Cap limit

//         const from = (page - 1) * limit;

//         const body = {
//             from,
//             size: limit,
//             sort: [{ "info.id": { order: "desc" } }], // Sort by ID as proxy for time
//             query: {
//                 match_all: {}
//             },
//             _source: ["target.file.name", "target.file.sha256", "info.score", "info.duration", "info.started", "info.id"], // Fetch necessary fields
//             track_total_hits: true
//         };

//         if (q) {
//             // Sanitize q (xss-clean handles basic stuff, but let's be safe)
//             const safeQ = String(q).trim();
//             if (safeQ) {
//                 body.query = {
//                     multi_match: {
//                         query: safeQ,
//                         fields: ["target.file.name", "target.file.sha256", "target.file.md5"]
//                     }
//                 };
//             }
//         }

//         const result = await esClient.search({
//             index: ES_INDEX,
//             body
//         });

//         const hits = result.hits.hits.map(hit => ({
//             id: hit._id,
//             ...hit._source
//         }));

//         res.json({
//             total: result.hits.total.value,
//             page: page,
//             limit: limit,
//             data: hits
//         });
//     } catch (error) {
//         console.error('ES Search Error:', error.message);
//         res.status(500).json({ error: 'Failed to search reports' });
//     }
// });

// // Get Single Report
// app.get('/api/es/reports/:id', authMiddleware, requireAdmin, async (req, res) => {
//     try {
//         const { id } = req.params;
//         // Validate ID format (alphanumeric, dashes, underscores)
//         if (!/^[a-zA-Z0-9\-_]+$/.test(id)) return res.status(400).json({ error: 'Invalid Report ID' });

//         const result = await esClient.get({
//             index: ES_INDEX,
//             id
//         });
//         res.json(result._source);
//     } catch (error) {
//         console.error('ES Get Error:', error.message);
//         if (error.meta && error.meta.statusCode === 404) {
//             return res.status(404).json({ error: 'Report not found' });
//         }
//         res.status(500).json({ error: 'Failed to fetch report' });
//     }
// });

// // --- ADMIN USER STATS ENDPOINTS ---

// // Get all users with stats
// app.get('/api/admin/users', authMiddleware, requireAdmin, async (req, res) => {
//     try {
//         // Aggregate Login History
//         // We want: username, role, lastLogin, totalLogins, totalSubmissions

//         // 1. Get all users from User collection (students)
//         // Admin user might not be in User collection if not using DB, so we handle that.

//         const users = await User.find().lean();

//         // 2. Get stats for each user (and any others found in LoginHistory/Submission)
//         // Aggregation is more efficient

//         const loginStats = await LoginHistory.aggregate([
//             { $group: { _id: "$username", count: { $sum: 1 }, lastLogin: { $max: "$timestamp" } } }
//         ]);

//         const submissionStats = await Submission.aggregate([
//             { $group: { _id: "$userId", count: { $sum: 1 }, lastSubmission: { $max: "$timestamp" } } }
//         ]);

//         // Merge data
//         const userMap = {};

//         // Initialize with known users
//         users.forEach(u => {
//             userMap[u.username] = {
//                 username: u.username,
//                 role: u.role,
//                 joinedAt: u.createdAt,
//                 lastLogin: u.lastLogin, // From User model
//                 totalLogins: 0,
//                 totalSubmissions: 0,
//                 lastSubmission: null
//             };
//         });

//         // Merge Login Stats
//         loginStats.forEach(stat => {
//             if (!userMap[stat._id]) {
//                 userMap[stat._id] = {
//                     username: stat._id,
//                     role: 'unknown',
//                     joinedAt: null,
//                     lastLogin: null,
//                     totalLogins: 0,
//                     totalSubmissions: 0,
//                     lastSubmission: null
//                 };
//             }
//             userMap[stat._id].totalLogins = stat.count;
//             // Prefer the history timestamp if newer
//             if (!userMap[stat._id].lastLogin || stat.lastLogin > userMap[stat._id].lastLogin) {
//                 userMap[stat._id].lastLogin = stat.lastLogin;
//             }
//             if (userMap[stat._id].role === 'unknown' && stat._id === ADMIN_USERNAME) {
//                 userMap[stat._id].role = 'admin';
//             }
//         });

//         // Merge Submission Stats
//         submissionStats.forEach(stat => {
//             if (!userMap[stat._id]) {
//                 // Should exist if they logged in, but just in case
//                 userMap[stat._id] = {
//                     username: stat._id,
//                     role: 'unknown',
//                     joinedAt: null,
//                     lastLogin: null,
//                     totalLogins: 0,
//                     totalSubmissions: 0,
//                     lastSubmission: null
//                 };
//             }
//             userMap[stat._id].totalSubmissions = stat.count;
//             userMap[stat._id].lastSubmission = stat.lastSubmission;
//         });

//         const result = Object.values(userMap).sort((a, b) => {
//             // Sort by last login desc, then username
//             const timeA = new Date(a.lastLogin || 0).getTime();
//             const timeB = new Date(b.lastLogin || 0).getTime();
//             return timeB - timeA;
//         });

//         res.json(result);

//     } catch (error) {
//         console.error('Error fetching user stats:', error);
//         res.status(500).json({ error: 'Failed to fetch user stats' });
//     }
// });

// // Get details for a specific user
// app.get('/api/admin/users/:username', authMiddleware, requireAdmin, async (req, res) => {
//     try {
//         const { username } = req.params;

//         // Parallel fetch
//         const [user, logins, submissions] = await Promise.all([
//             User.findOne({ username }).lean(),
//             LoginHistory.find({ username }).sort({ timestamp: -1 }).limit(50).lean(),
//             Submission.find({ userId: username }).sort({ timestamp: -1 }).limit(50).lean()
//         ]);

//         // Refresh status of non-terminal submissions from CAPE API
//         const terminalStatuses = ['reported', 'completed', 'success', 'error', 'failed', 'timedout'];
//         const pendingSubs = submissions.filter(s =>
//             s.taskId && !terminalStatuses.includes((s.status || '').toLowerCase())
//         );

//         if (pendingSubs.length > 0) {
//             await Promise.allSettled(
//                 pendingSubs.map(async (sub) => {
//                     try {
//                         const url = `${CAPE_API_BASE}/apiv2/tasks/status/${sub.taskId}`;
//                         const response = await axios.get(url, { timeout: 5000 });
//                         const rawData = response.data?.data;
//                         const status = typeof rawData === 'string' ? rawData : (rawData?.status || response.data?.status);
//                         if (status) {
//                             const lowerStatus = status.toLowerCase();
//                             await Submission.findOneAndUpdate(
//                                 { taskId: sub.taskId },
//                                 { status: lowerStatus }
//                             );
//                             sub.status = lowerStatus; // update the response object too
//                         }
//                     } catch (_) {
//                         // Ignore individual CAPE API failures
//                     }
//                 })
//             );
//         }

//         res.json({
//             user: user || { username, role: 'unknown' },
//             loginHistory: logins,
//             submissions: submissions
//         });

//     } catch (error) {
//         console.error('Error fetching user details:', error);
//         res.status(500).json({ error: 'Failed to fetch user details' });
//     }
// });

// // Lookup submission by Task ID (returns username)
// app.get('/api/admin/submission-lookup/:taskId', authMiddleware, requireAdmin, async (req, res) => {
//     try {
//         const { taskId } = req.params;
//         if (!taskId || !taskId.trim()) return res.status(400).json({ error: 'Task ID required' });

//         const submission = await Submission.findOne({ taskId: taskId.trim() }).lean();
//         if (!submission) return res.status(404).json({ error: 'No submission found for this Task ID' });

//         res.json({
//             taskId: submission.taskId,
//             username: submission.userId,
//             filename: submission.filename,
//             status: submission.status,
//             timestamp: submission.timestamp
//         });
//     } catch (error) {
//         console.error('Error looking up submission:', error);
//         res.status(500).json({ error: 'Failed to look up submission' });
//     }
// });

// // Get restriction status
// app.get('/api/admin/restriction-status', authMiddleware, requireAdmin, (req, res) => {
//     res.json({ enabled: submissionRestrictionEnabled });
// });

// // Toggle restriction
// app.post('/api/admin/toggle-restriction', authMiddleware, requireAdmin, (req, res) => {
//     submissionRestrictionEnabled = !submissionRestrictionEnabled;
//     res.json({ enabled: submissionRestrictionEnabled });
// });

// // Dashboard Stats Endpoint
// app.get('/api/admin/dashboard-stats', authMiddleware, requireAdmin, async (req, res) => {
//     try {
//         // Support optional ?date=YYYY-MM-DD query parameter
//         let startOfDay, endOfDay, dateLabel;
//         if (req.query.date) {
//             const parsed = new Date(req.query.date + 'T00:00:00');
//             if (isNaN(parsed.getTime())) {
//                 return res.status(400).json({ error: 'Invalid date format. Use YYYY-MM-DD.' });
//             }
//             startOfDay = parsed;
//             endOfDay = new Date(parsed);
//             endOfDay.setDate(endOfDay.getDate() + 1);
//             dateLabel = req.query.date;
//         } else {
//             const now = new Date();
//             startOfDay = new Date(now.getFullYear(), now.getMonth(), now.getDate());
//             endOfDay = new Date(startOfDay);
//             endOfDay.setDate(endOfDay.getDate() + 1);
//             dateLabel = 'today';
//         }

//         // 1. Summary Counts
//         const totalUsers = await User.countDocuments();
//         const totalSubmissions = await Submission.countDocuments();
//         const loginsOnDate = await LoginHistory.countDocuments({ timestamp: { $gte: startOfDay, $lt: endOfDay } });
//         const submissionsOnDate = await Submission.countDocuments({ timestamp: { $gte: startOfDay, $lt: endOfDay } });

//         // 2. Timeline (Last 30 Days)
//         const thirtyDaysAgo = new Date();
//         thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

//         const loginTimeline = await LoginHistory.aggregate([
//             { $match: { timestamp: { $gte: thirtyDaysAgo } } },
//             {
//                 $group: {
//                     _id: { $dateToString: { format: "%Y-%m-%d", date: "$timestamp" } },
//                     count: { $sum: 1 }
//                 }
//             },
//             { $sort: { _id: 1 } }
//         ]);

//         const submissionTimeline = await Submission.aggregate([
//             { $match: { timestamp: { $gte: thirtyDaysAgo } } },
//             {
//                 $group: {
//                     _id: { $dateToString: { format: "%Y-%m-%d", date: "$timestamp" } },
//                     count: { $sum: 1 }
//                 }
//             },
//             { $sort: { _id: 1 } }
//         ]);

//         // 3. File Type Distribution
//         const fileTypes = await Submission.aggregate([
//             { $group: { _id: "$package", count: { $sum: 1 } } },
//             { $sort: { count: -1 } }
//         ]);

//         // 4. Top Users (by submission)
//         const topUsers = await Submission.aggregate([
//             { $group: { _id: "$userId", count: { $sum: 1 } } },
//             { $sort: { count: -1 } },
//             { $limit: 5 }
//         ]);

//         res.json({
//             summary: {
//                 totalUsers,
//                 totalSubmissions,
//                 loginsOnDate,
//                 submissionsOnDate,
//                 dateLabel
//             },
//             timeline: {
//                 logins: loginTimeline,
//                 submissions: submissionTimeline
//             },
//             fileTypes,
//             topUsers
//         });

//     } catch (error) {
//         console.error('Error fetching dashboard stats:', error);
//         res.status(500).json({ error: 'Failed to fetch dashboard stats' });
//     }
// });

// // --- IP Geolocation Proxy ---
// // Proxies geolocation lookups through the server so they work even when
// // the university network blocks direct browser requests to third-party APIs.
// const geoLimiter = rateLimit({
//     windowMs: 15 * 60 * 1000,
//     max: 300, // generous limit for geo lookups
//     message: { error: 'Too many geolocation requests' }
// });
// app.get('/api/geoip/:ip', geoLimiter, async (req, res) => {
//     const ip = req.params.ip;
//     // Basic IPv4/IPv6 validation
//     if (!/^[\d.:a-fA-F]+$/.test(ip)) return res.status(400).json({ error: 'Invalid IP' });

//     const apis = [
//         {
//             url: `https://ipapi.co/${ip}/json/`,
//             parse: d => ({
//                 city: d.city, region: d.region, country: d.country_name,
//                 lat: d.latitude, lon: d.longitude
//             })
//         },
//         {
//             url: `https://ipwhois.app/json/${ip}`,
//             parse: d => ({
//                 city: d.city, region: d.region, country: d.country,
//                 lat: d.latitude, lon: d.longitude
//             })
//         },
//         {
//             url: `https://ipapi.com/ip_api.php?ip=${ip}`,
//             parse: d => ({
//                 city: d.city, region: d.regionName || d.region, country: d.countryName || d.country_name,
//                 lat: d.latitude || d.lat, lon: d.longitude || d.lon
//             })
//         },
//         {
//             url: `https://json.geoiplookup.io/${ip}`,
//             parse: d => ({
//                 city: d.city, region: d.region, country: d.country_name,
//                 lat: d.latitude, lon: d.longitude
//             })
//         },
//         {
//             url: `https://api.ip.sb/geoip/${ip}`,
//             parse: d => ({
//                 city: d.city, region: d.region, country: d.country,
//                 lat: d.latitude, lon: d.longitude
//             })
//         }
//     ];

//     for (const api of apis) {
//         try {
//             const response = await axios.get(api.url, { timeout: 5000 });
//             const parsed = api.parse(response.data);
//             if (parsed.city || parsed.country) {
//                 const location = `${parsed.city || 'Unknown'}, ${parsed.region || 'Unknown'}, ${parsed.country || 'Unknown'}`;
//                 return res.json({
//                     ip,
//                     location,
//                     city: parsed.city || 'Unknown',
//                     region: parsed.region || 'Unknown',
//                     country: parsed.country || 'Unknown',
//                     lat: parsed.lat ? parseFloat(parsed.lat) : null,
//                     lon: parsed.lon ? parseFloat(parsed.lon) : null
//                 });
//             }
//         } catch (e) {
//             // try next API
//             continue;
//         }
//     }
//     // All APIs failed
//     return res.status(502).json({ error: 'All geolocation APIs failed', ip });
// });

// const HOST = process.env.HOST || '0.0.0.0';
// app.listen(PORT, HOST, () => {
//     console.log(`Server running on http://${HOST}:${PORT}`);
//     console.log(`Access the CAPE upload interface at http://${HOST}:${PORT}`);
// });



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

// Basic rate limiting — generous for an interactive SPA which polls
// /api/health, /api/submissions, /api/task/:id every few seconds.
// /api/health is exempted (it is a tiny status probe used by the topbar).
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 1500,                // ~1.6 req/sec sustained per IP
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests from this IP, please slow down.' },
    skip: (req) => req.path === '/api/health' || req.path.startsWith('/reports/')
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

// ============== MongoDB connection ==============
let mongoConnected = false;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/cape';
mongoose.connect(MONGODB_URI, { serverSelectionTimeoutMS: 8000 })
    .then(() => { mongoConnected = true; console.log('MongoDB connected'); })
    .catch(err => {
        mongoConnected = false;
        console.warn('MongoDB connection failed; using in-memory fallback. Reason:', err.message);
    });
mongoose.connection.on('connected', () => { mongoConnected = true; });
mongoose.connection.on('disconnected', () => { mongoConnected = false; });

// Submission schema for Mongoose
const submissionSchema = new mongoose.Schema({
    taskId: { type: String, required: true },
    filename: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    status: { type: String, default: 'pending' },
    userId: { type: String, required: true },
    package: { type: String, default: 'exe' },
    timeout: { type: Number, default: 300 },
    priority: { type: Number, default: 1 },
    size: Number,
    mimetype: String,
    verdict: String,        // bot-classified: malicious | suspicious | benign | unknown
    verdictNote: String,    // 1-line justification
    tags: [String]          // auto-extracted tags: ransomware, downloader, etc.
});
const Submission = mongoose.model('Submission', submissionSchema);

// In-memory submission store (used when Mongo is unreachable).
// Keyed by taskId; also indexed by userId for listing.
const memSubs = new Map();
function memListByUser(userId) {
    const out = [];
    for (const s of memSubs.values()) if (s.userId === userId) out.push({ ...s });
    out.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    return out;
}
function memUpsert(taskId, patch) {
    const cur = memSubs.get(String(taskId)) || {};
    const next = { ...cur, ...patch, taskId: String(taskId) };
    memSubs.set(String(taskId), next);
    return next;
}
function memDelete(taskId, userId) {
    const cur = memSubs.get(String(taskId));
    if (cur && (!userId || cur.userId === userId)) {
        memSubs.delete(String(taskId));
        return true;
    }
    return false;
}

// Storage abstraction: writes go to BOTH Mongo (best effort) and memory.
// Reads: prefer Mongo when connected, else memory.
function storeReady() { return mongoConnected; }

async function storeListSubmissions(userId) {
    if (mongoConnected) {
        try {
            const docs = await Submission.find({ userId }).sort({ timestamp: -1 }).limit(100);
            return docs.map(d => d.toObject());
        } catch (e) {
            console.warn('Mongo list failed, fallback to memory:', e.message);
        }
    }
    return memListByUser(userId);
}
async function storeCreateSubmission(doc) {
    memUpsert(doc.taskId, doc);
    if (mongoConnected) {
        try { await Submission.create(doc); } catch (e) { console.warn('Mongo create failed:', e.message); }
    }
    return doc;
}
async function storeUpdateSubmission(taskId, userId, patch) {
    const merged = memUpsert(taskId, { ...patch, userId });
    if (mongoConnected) {
        try { await Submission.findOneAndUpdate({ taskId: String(taskId), userId }, patch); }
        catch (e) { console.warn('Mongo update failed:', e.message); }
    }
    return merged;
}
async function storeDeleteSubmission(taskId, userId) {
    memDelete(taskId, userId);
    if (mongoConnected) {
        try { await Submission.deleteOne({ taskId: String(taskId), userId }); }
        catch (e) { console.warn('Mongo delete failed:', e.message); }
    }
}

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
                if (mongoConnected) {
                    try {
                        await User.findOneAndUpdate(
                            { username },
                            {
                                $setOnInsert: {
                                    username, role: 'student', createdAt: new Date(),
                                    email: `${username}@student.local`
                                },
                                $set: { lastLogin: new Date() }
                            },
                            { upsert: true, new: true }
                        );
                    } catch (dbErr) { console.error('Error saving user to DB:', dbErr.message); }
                }
                await writeLog('auth.log', { type: 'login_success', ip: req.ip, username, role });
            }
        }
        // Check for Admin Login
        else if (username === ADMIN_USERNAME) {
            if (ADMIN_PASSWORD_HASH) {
                try { isAuthenticated = await argon2.verify(ADMIN_PASSWORD_HASH, password); }
                catch (_) { isAuthenticated = false; }
            } else if (ADMIN_PASSWORD) {
                isAuthenticated = password === ADMIN_PASSWORD;
            }
            if (isAuthenticated) {
                role = 'admin';
                await writeLog('auth.log', { type: 'login_success', ip: req.ip, username, role });
            }
        }

        if (isAuthenticated && mongoConnected) {
            try {
                await LoginHistory.create({
                    username, role, ip: req.ip, userAgent: req.headers['user-agent']
                });
            } catch (histErr) { console.error('Error saving login history:', histErr.message); }
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
        const submissions = await storeListSubmissions(req.user.username);
        res.json(submissions);
    } catch (error) {
        console.error('Error fetching submissions:', error);
        res.status(500).json({ error: 'Failed to fetch submission history' });
    }
});

// Bulk-refresh statuses of non-terminal submissions from CAPE API
app.post('/api/submissions/refresh', authMiddleware, async (req, res) => {
    try {
        const submissions = await storeListSubmissions(req.user.username);
        const terminalStatuses = ['reported', 'completed', 'success', 'error', 'failed', 'timedout'];
        const pendingSubs = submissions.filter(s =>
            s.taskId && !terminalStatuses.includes((s.status || '').toLowerCase())
        );
        let updated = 0;
        if (pendingSubs.length > 0) {
            await Promise.allSettled(pendingSubs.map(async (sub) => {
                try {
                    let status;
                    const url = `${CAPE_API_BASE}/apiv2/tasks/status/${sub.taskId}`;
                    const response = await axios.get(url, { timeout: 5000 });
                    const rawData = response.data?.data;
                    status = typeof rawData === 'string' ? rawData : (rawData?.status || response.data?.status);
                    if (status) {
                        const lowerStatus = status.toLowerCase();
                        if (lowerStatus !== (sub.status || '').toLowerCase()) {
                            await storeUpdateSubmission(sub.taskId, req.user.username, { status: lowerStatus });
                            // Trigger auto-verdict if newly reported
                            if (lowerStatus === 'reported') {
                                triggerAutoEnrich(sub.taskId, req.user.username).catch(() => { });
                            }
                            updated++;
                        }
                    }
                } catch (_) { /* per-task failures ignored */ }
            }));
        }
        const refreshed = await storeListSubmissions(req.user.username);
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
        const updated = await storeUpdateSubmission(taskId, req.user.username, { status });
        if (!updated) return res.status(404).json({ error: 'Submission not found' });
        res.json(updated);
    } catch (error) {
        console.error('Error updating submission:', error);
        res.status(500).json({ error: 'Failed to update submission' });
    }
});

// Delete a submission
app.delete('/api/submissions/:taskId', authMiddleware, async (req, res) => {
    try {
        const { taskId } = req.params;
        await storeDeleteSubmission(taskId, req.user.username);
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting submission:', error);
        res.status(500).json({ error: 'Failed to delete submission' });
    }
});

// Multer wrapper that converts MulterError (e.g. "Unexpected field" when the
// client uses a wrong form-field name, or "File too large") into a clean 400
// instead of letting Express fall through to a 500.
function uploadFile(req, res, next) {
    upload.single('file')(req, res, (err) => {
        if (!err) return next();
        const isMulter = err.name === 'MulterError' || err.code;
        const status = isMulter ? 400 : 500;
        const message =
            err.code === 'LIMIT_FILE_SIZE' ? 'File is too large (max 50 MB)' :
                err.code === 'LIMIT_UNEXPECTED_FILE' ? 'Form field for the file must be named "file"' :
                    err.code === 'LIMIT_FILE_COUNT' ? 'Only one file can be uploaded at a time' :
                        isMulter ? `Upload error: ${err.message}` :
                            'Unexpected upload error';
        return res.status(status).json({ error: message, code: err.code || null });
    });
}

// Handle file upload to CAPE API (protected)
app.post('/api/upload', authMiddleware, uploadFile, async (req, res) => {
    try {
        const file = req.file;
        const { package: packageType, timeout, priority } = req.body;

        if (!file) {
            await writeLog('tasks.log', { type: 'submit_missing_file', ip: req.ip, user: userFromReq(req) });
            return res.status(400).json({ error: 'No file provided' });
        }

        // Validate inputs
        const validPackages = ['exe', 'dll', 'zip', 'apk', 'office', 'pdf', 'browser', 'chrome', 'firefox', 'ie'];
        // If package is 'auto' or not provided, let CAPE auto-detect — don't default to 'exe'
        const pkg = (packageType && packageType !== 'auto' && validPackages.includes(packageType)) ? packageType : null;
        const tm = Math.min(Math.max(parseInt(timeout) || 300, 100), 300); // 100s to 300s
        // Only admin users can set custom priority; students are forced to 1
        const prio = (req.user && (req.user.role === 'admin' || req.user.role === 'root'))
            ? Math.min(Math.max(parseInt(priority) || 1, 1), 5)
            : 1;

        // Rate limit check (uses storage abstraction)
        if (submissionRestrictionEnabled && req.user && req.user.role !== 'admin' && req.user.role !== 'root') {
            const fiveHoursAgo = Date.now() - 5 * 60 * 60 * 1000;
            const all = await storeListSubmissions(req.user.username);
            const recent = all.filter(s => new Date(s.timestamp).getTime() >= fiveHoursAgo).length;
            if (recent >= 5) {
                await writeLog('tasks.log', { type: 'submit_rate_limited', ip: req.ip, user: userFromReq(req) });
                return res.status(429).json({ error: 'Submission limit reached. Max 5 submissions per 5 hours.' });
            }
        }

        await writeLog('tasks.log', {
            type: 'submit_attempt', ip: req.ip, user: userFromReq(req),
            filename: file.originalname, size: file.size, mimetype: file.mimetype,
            package: pkg, timeout: tm, priority: prio
        });

        const formData = new FormData();
        formData.append('file', file.buffer, { filename: file.originalname, contentType: file.mimetype });
        if (pkg) {
            formData.append('package', pkg);
        }
        formData.append('timeout', String(tm));
        formData.append('priority', String(prio));

        const response = await axios.post(CAPE_API_UPLOAD_URL, formData, {
            headers: { ...formData.getHeaders() },
            maxContentLength: Infinity, maxBodyLength: Infinity
        });
        const upstreamData = response.data;
        console.log('CAPE API Upload Response:', JSON.stringify(upstreamData, null, 2));
        const taskIds = upstreamData?.data?.task_ids || upstreamData?.task_ids || [];
        const taskId = taskIds[0];

        if (taskId) {
            try {
                await storeCreateSubmission({
                    taskId: String(taskId),
                    filename: file.originalname,
                    userId: req.user.username,
                    package: pkg,
                    timeout: tm,
                    priority: prio,
                    size: file.size,
                    mimetype: file.mimetype,
                    status: 'pending',
                    timestamp: new Date()
                });
            } catch (e) { console.error('Error saving submission:', e.message); }
        }

        await writeLog('tasks.log', {
            type: 'submit_success', ip: req.ip, user: userFromReq(req),
            filename: file.originalname, taskId
        });

        res.json(upstreamData);
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
        const response = await axios.get(url);
        const rawData = response.data?.data;
        const status = typeof rawData === 'string' ? rawData : (rawData?.status || response.data?.status);
        const respData = response.data;

        if (status) {
            const lower = status.toLowerCase();
            try {
                await storeUpdateSubmission(taskId, req.user.username, { status: lower });
                if (lower === 'reported') {
                    triggerAutoEnrich(taskId, req.user.username).catch(() => { });
                }
            } catch (e) { /* ignore */ }
        }
        await writeLog('tasks.log', { type: 'status_view', ip: req.ip, user: userFromReq(req), taskId, status });
        res.json(respData);
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

        const outName = `report_${taskId}.json`;
        const outPath = path.join(REPORTS_DIR, outName);

        const url = `${CAPE_API_BASE}/apiv2/tasks/get/report/${taskId}`;
        console.log('Fetching report for visualiser', { taskId, url });
        const response = await axios.get(url, { responseType: 'arraybuffer' });
        try {
            await fsp.writeFile(outPath, response.data);
        } catch (err) {
            console.error('Error writing report file:', err.message);
            return res.status(500).json({ error: 'Failed to save report file' });
        }

        await writeLog('tasks.log', { type: 'visualise_saved', ip: req.ip, user: userFromReq(req), taskId, outPath });
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
        res.set('Content-Type', response.headers['content-type'] || 'application/octet-stream');
        res.set('Content-Disposition', response.headers['content-disposition'] || `attachment; filename="report_${taskId}"`);
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
        res.set('Content-Type', 'text/html');
        res.send(response.data);
    } catch (error) {
        await writeLog('tasks.log', { type: 'report_view_error', ip: req.ip, user: userFromReq(req), taskId: req.params?.taskId, error: error.message });
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// IoCs view (CAPE-style JSON)
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
        res.set('Content-Type', response.headers['content-type'] || 'application/octet-stream');
        res.set('Content-Disposition', response.headers['content-disposition'] || `attachment; filename="screenshots_${taskId}.zip"`);
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
        // When Mongo isn't reachable, build a best-effort summary from the
        // in-memory submission store so the admin dashboard still renders.
        if (!mongoConnected) {
            const userMap = {};
            for (const sub of memSubs.values()) {
                const u = sub.userId || 'unknown';
                if (!userMap[u]) userMap[u] = {
                    username: u, role: u === ADMIN_USERNAME ? 'admin' : 'student',
                    joinedAt: null, lastLogin: null,
                    totalLogins: 0, totalSubmissions: 0, lastSubmission: null
                };
                userMap[u].totalSubmissions++;
                const ts = sub.timestamp ? new Date(sub.timestamp) : null;
                if (ts && (!userMap[u].lastSubmission || ts > new Date(userMap[u].lastSubmission))) {
                    userMap[u].lastSubmission = ts;
                }
            }
            return res.json(Object.values(userMap));
        }

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

        // Mongo-down fallback: build response from in-memory submission store.
        if (!mongoConnected) {
            const subs = memListByUser(username);
            return res.json({
                user: { username, role: username === ADMIN_USERNAME ? 'admin' : 'student' },
                loginHistory: [],
                submissions: subs.slice(0, 50)
            });
        }

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
        const tid = taskId.trim();

        // Try Mongo when reachable; otherwise (and on Mongo error) fall through
        // to the in-memory store. Either way, we never 500 for a missing row.
        let submission = null;
        if (mongoConnected) {
            try { submission = await Submission.findOne({ taskId: tid }).lean(); }
            catch (e) { console.warn('Mongo lookup failed, trying memory:', e.message); }
        }
        if (!submission) submission = memSubs.get(tid) || null;

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

        // ---------- Mongo-down fallback ----------
        // Compute everything from the in-memory submission store so the
        // dashboard renders meaningfully even without a database. We still
        // return the same response shape the frontend expects.
        if (!mongoConnected) {
            const allSubs = Array.from(memSubs.values());
            const userSet = new Set(allSubs.map(s => s.userId).filter(Boolean));

            const submissionsOnDate = allSubs.filter(s => {
                const t = s.timestamp ? new Date(s.timestamp) : null;
                return t && t >= startOfDay && t < endOfDay;
            }).length;

            const thirtyDaysAgo = new Date();
            thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
            const byDay = {};
            for (const s of allSubs) {
                const t = s.timestamp ? new Date(s.timestamp) : null;
                if (!t || t < thirtyDaysAgo) continue;
                const k = t.toISOString().slice(0, 10);
                byDay[k] = (byDay[k] || 0) + 1;
            }
            const submissionTimeline = Object.keys(byDay).sort()
                .map(k => ({ _id: k, count: byDay[k] }));

            const fileTypeMap = {};
            for (const s of allSubs) {
                const k = s.package || 'unknown';
                fileTypeMap[k] = (fileTypeMap[k] || 0) + 1;
            }
            const fileTypes = Object.entries(fileTypeMap)
                .map(([k, count]) => ({ _id: k, count }))
                .sort((a, b) => b.count - a.count);

            const topUsersMap = {};
            for (const s of allSubs) {
                if (!s.userId) continue;
                topUsersMap[s.userId] = (topUsersMap[s.userId] || 0) + 1;
            }
            const topUsers = Object.entries(topUsersMap)
                .map(([_id, count]) => ({ _id, count }))
                .sort((a, b) => b.count - a.count).slice(0, 5);

            return res.json({
                summary: {
                    totalUsers: userSet.size,
                    totalSubmissions: allSubs.length,
                    loginsOnDate: 0, // unknown without DB
                    submissionsOnDate,
                    dateLabel
                },
                timeline: { logins: [], submissions: submissionTimeline },
                fileTypes,
                topUsers,
                _source: 'in-memory-fallback'
            });
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

// --- CyberHelp Chatbot (Hugging Face) ---
// Topic-restricted assistant: answers ONLY CapeUI / CAPE sandbox / malware /
// cybersecurity questions. Off-topic questions are politely refused.
// When a task_id is provided, fetches that task's CAPE JSON report and
// injects a compact summary into the LLM context so the bot can answer
// questions like "summarize this report" or "what IOCs are in this run".
const HF_API_TOKEN = process.env.HF_API_TOKEN || '';
const HF_MODEL = process.env.HF_MODEL || 'mistralai/Mistral-7B-Instruct-v0.3';
const HF_API_URL = process.env.HF_API_URL || 'https://router.huggingface.co/v1/chat/completions';

const chatLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 20,
    message: { error: 'Too many chat requests, slow down a bit.' }
});

// --- CAPE report cache + summarizer ---
const REPORT_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const reportCache = new Map(); // taskId(string) -> { summary, fetchedAt }

async function fetchCapeReportJson(taskId) {
    const url = `${CAPE_API_BASE}/apiv2/tasks/get/report/${taskId}`;
    const resp = await axios.get(url, { responseType: 'json', timeout: 30000 });
    return resp.data?.data && typeof resp.data.data === 'object' ? resp.data.data : resp.data;
}

function trimArr(arr, n) {
    if (!Array.isArray(arr)) return [];
    return arr.slice(0, n);
}
function truncStr(s, n) {
    if (typeof s !== 'string') return s;
    return s.length > n ? s.slice(0, n) + '…' : s;
}

// Build a compact, LLM-friendly text summary of a CAPE report.
// Aim: < ~9 KB so it fits comfortably alongside system prompt + history.
function summarizeCapeReport(report) {
    if (!report || typeof report !== 'object') {
        return 'No report data available.';
    }

    const lines = [];
    const info = report.info || {};
    const target = report.target || {};
    const file = target.file || target.url || {};
    const sigs = report.signatures || [];
    const beh = report.behavior || {};
    const net = report.network || {};
    const dropped = report.dropped || [];
    const procs = beh.processes || [];
    const summary = beh.summary || {};
    const mitre = report.ttps || report.mitre || report.mitre_attack || [];
    const malscore = report.malscore ?? report.score ?? null;
    const detections = report.detections || report.detection || null;

    lines.push('=== CAPE TASK INFO ===');
    lines.push(`task_id: ${info.id ?? 'N/A'}`);
    lines.push(`package: ${info.package ?? 'N/A'}`);
    lines.push(`category: ${info.category ?? 'N/A'}`);
    lines.push(`started: ${info.started ?? 'N/A'}`);
    lines.push(`ended:   ${info.ended ?? 'N/A'}`);
    lines.push(`duration_sec: ${info.duration ?? 'N/A'}`);
    lines.push(`machine: ${info.machine?.name ?? info.machine ?? 'N/A'}`);
    lines.push(`platform: ${info.platform ?? 'N/A'}`);
    if (malscore !== null) lines.push(`malscore: ${malscore}`);
    if (detections) lines.push(`detections: ${typeof detections === 'string' ? detections : JSON.stringify(detections).slice(0, 300)}`);

    lines.push('\n=== TARGET ===');
    if (file && typeof file === 'object') {
        lines.push(`name: ${file.name ?? 'N/A'}`);
        lines.push(`size: ${file.size ?? 'N/A'}`);
        lines.push(`type: ${truncStr(file.type ?? '', 200)}`);
        lines.push(`md5:    ${file.md5 ?? 'N/A'}`);
        lines.push(`sha1:   ${file.sha1 ?? 'N/A'}`);
        lines.push(`sha256: ${file.sha256 ?? 'N/A'}`);
        if (file.crc32) lines.push(`crc32:  ${file.crc32}`);
        if (file.ssdeep) lines.push(`ssdeep: ${truncStr(file.ssdeep, 120)}`);
        if (file.entropy) lines.push(`entropy: ${file.entropy}`);
    }

    if (Array.isArray(sigs) && sigs.length) {
        lines.push(`\n=== SIGNATURES (${sigs.length} matched, top 12 by severity) ===`);
        const sorted = sigs.slice().sort((a, b) => (b.severity ?? 0) - (a.severity ?? 0));
        for (const s of trimArr(sorted, 12)) {
            const name = s.name || s.short_description || 'unnamed';
            const desc = s.description || '';
            const sev = s.severity ?? '?';
            const conf = s.confidence ?? '?';
            lines.push(`- [sev=${sev} conf=${conf}] ${name}: ${truncStr(desc, 220)}`);
        }
    }

    if (Array.isArray(mitre) && mitre.length) {
        lines.push(`\n=== MITRE ATT&CK TTPs (top 15) ===`);
        for (const t of trimArr(mitre, 15)) {
            const id = t.t_id || t.technique_id || t.id || t.ttp || '?';
            const name = t.name || t.technique || t.description || '';
            const tactics = Array.isArray(t.tactics) ? t.tactics.join(',') : (t.tactic || '');
            lines.push(`- ${id}${tactics ? ' [' + tactics + ']' : ''} ${name ? '— ' + truncStr(String(name), 160) : ''}`);
        }
    }

    // Network IOCs
    const dnsArr = trimArr(net.dns, 20);
    const httpArr = trimArr(net.http, 15);
    const hostsArr = trimArr(net.hosts, 25);
    const tcpArr = trimArr(net.tcp, 10);
    if (dnsArr.length || httpArr.length || hostsArr.length || tcpArr.length) {
        lines.push('\n=== NETWORK ===');
        if (hostsArr.length) {
            const ips = hostsArr.map(h => typeof h === 'string' ? h : (h.ip || h.address || JSON.stringify(h))).filter(Boolean);
            lines.push(`hosts (${net.hosts?.length || 0}): ${trimArr(ips, 25).join(', ')}`);
        }
        if (dnsArr.length) {
            lines.push(`dns_queries (${net.dns?.length || 0}):`);
            for (const d of dnsArr) {
                const req = d.request || d.hostname || d.query || JSON.stringify(d);
                const ans = Array.isArray(d.answers) ? d.answers.map(a => a.data || a).slice(0, 4).join('|') : '';
                lines.push(`  - ${truncStr(String(req), 120)}${ans ? ' -> ' + truncStr(ans, 120) : ''}`);
            }
        }
        if (httpArr.length) {
            lines.push(`http_requests (${net.http?.length || 0}):`);
            for (const h of httpArr) {
                const m = h.method || 'GET';
                const u = h.uri || h.url || h.host || '';
                lines.push(`  - ${m} ${truncStr(String(u), 200)}`);
            }
        }
        if (tcpArr.length) {
            const tcps = tcpArr.map(t => `${t.src || ''}:${t.sport || ''}->${t.dst || ''}:${t.dport || ''}`);
            lines.push(`tcp (${net.tcp?.length || 0}): ${tcps.join(', ')}`);
        }
    }

    // Behavior summary (file/registry/mutex/services IOCs)
    const fileWrites = trimArr(summary.write_files || summary.file_written, 20);
    const fileDels = trimArr(summary.delete_files || summary.file_deleted, 15);
    const fileReads = trimArr(summary.read_files || summary.file_read, 10);
    const regWrites = trimArr(summary.write_keys || summary.regkey_written, 20);
    const regReads = trimArr(summary.read_keys || summary.regkey_read, 10);
    const mutexes = trimArr(summary.mutexes || summary.mutex, 15);
    const cmdLines = trimArr(summary.executed_commands || summary.command_line, 10);
    if (fileWrites.length || regWrites.length || mutexes.length || cmdLines.length) {
        lines.push('\n=== BEHAVIOR HIGHLIGHTS ===');
        if (cmdLines.length) {
            lines.push('commands_executed:');
            for (const c of cmdLines) lines.push(`  - ${truncStr(String(c), 240)}`);
        }
        if (fileWrites.length) {
            lines.push(`files_written (${(summary.write_files || []).length || fileWrites.length}):`);
            for (const f of fileWrites) lines.push(`  - ${truncStr(String(f), 200)}`);
        }
        if (fileDels.length) {
            lines.push(`files_deleted (${(summary.delete_files || []).length || fileDels.length}):`);
            for (const f of fileDels) lines.push(`  - ${truncStr(String(f), 200)}`);
        }
        if (fileReads.length) {
            lines.push(`files_read_sample: ${fileReads.map(s => truncStr(String(s), 80)).join(' | ')}`);
        }
        if (regWrites.length) {
            lines.push(`registry_keys_written (${(summary.write_keys || []).length || regWrites.length}):`);
            for (const r of regWrites) lines.push(`  - ${truncStr(String(r), 200)}`);
        }
        if (regReads.length) {
            lines.push(`registry_keys_read_sample: ${regReads.map(s => truncStr(String(s), 80)).join(' | ')}`);
        }
        if (mutexes.length) {
            lines.push(`mutexes (${(summary.mutexes || []).length || mutexes.length}): ${mutexes.map(m => truncStr(String(m), 80)).join(', ')}`);
        }
    }

    if (Array.isArray(procs) && procs.length) {
        lines.push(`\n=== PROCESSES (${procs.length} total, top 10) ===`);
        for (const p of trimArr(procs, 10)) {
            const pid = p.pid ?? p.process_id ?? '?';
            const ppid = p.parent_id ?? p.ppid ?? '?';
            const name = p.process_name || p.name || '?';
            const cmd = p.command_line || p.cmd_line || p.environ?.CommandLine || '';
            lines.push(`- pid=${pid} ppid=${ppid} ${name}${cmd ? ' :: ' + truncStr(String(cmd), 200) : ''}`);
        }
    }

    if (Array.isArray(dropped) && dropped.length) {
        lines.push(`\n=== DROPPED FILES (${dropped.length} total, top 10) ===`);
        for (const d of trimArr(dropped, 10)) {
            lines.push(`- ${d.name || d.filepath || '?'} sha256=${d.sha256 || '?'} type=${truncStr(String(d.type || ''), 100)}`);
        }
    }

    let text = lines.join('\n');
    // Hard cap to keep prompt manageable
    if (text.length > 9000) text = text.slice(0, 9000) + '\n…[truncated]';
    return text;
}

// ============== Auto verdict + tags ==============
function deriveVerdict(report) {
    const score = Number(report?.malscore ?? report?.score ?? 0);
    const sigs = Array.isArray(report?.signatures) ? report.signatures : [];
    const maxSev = sigs.reduce((m, s) => Math.max(m, Number(s.severity || 0)), 0);
    const ttps = (report?.ttps || report?.mitre || []);
    const ttpCount = Array.isArray(ttps) ? ttps.length : 0;
    let verdict = 'unknown';
    if (score >= 7 || maxSev >= 5 || ttpCount >= 4) verdict = 'malicious';
    else if (score >= 4 || maxSev >= 3 || ttpCount >= 1) verdict = 'suspicious';
    else if (sigs.length === 0 && score === 0) verdict = 'unknown';
    else verdict = 'benign';
    const note =
        verdict === 'malicious' ? `High-confidence malicious (malscore ${score}, ${sigs.length} signatures, ${ttpCount} TTPs).` :
            verdict === 'suspicious' ? `Suspicious behavior detected (malscore ${score}, ${sigs.length} signatures).` :
                verdict === 'benign' ? `No high-severity behavior observed.` : `Insufficient data for verdict.`;
    return { verdict, verdictNote: note, score, maxSev };
}

function deriveTags(report) {
    const tags = new Set();
    const sigs = Array.isArray(report?.signatures) ? report.signatures : [];
    const summary = report?.behavior?.summary || {};
    const text = JSON.stringify({ sigs, summary }).toLowerCase();

    const map = [
        ['ransomware', ['ransomware', 'encrypt_files', 'shadow_copy_delete', 'cryptdll', 'ransom']],
        ['downloader', ['downloader', 'download_url', 'wininet_download']],
        ['infostealer', ['infostealer', 'stealer', 'browser_credentials', 'cookies', 'wallet']],
        ['rat', ['remote_access', 'rat_', 'reverse_shell', 'remote_command']],
        ['c2', ['command_and_control', 'c2', 'beacon']],
        ['persistence', ['persistence', 'run_key', 'scheduled_task', 'autorun']],
        ['injection', ['process_injection', 'process_hollowing', 'inject']],
        ['evasion', ['anti_debug', 'antivm', 'antidebug', 'anti_vm', 'evasion']],
        ['network', ['network_connect', 'http_request', 'dns_query']],
        ['packed', ['packed', 'upx', 'high_entropy']],
        ['dropper', ['drops_pe', 'creates_exe', 'drops_exe']]
    ];
    for (const [tag, keys] of map) {
        if (keys.some(k => text.includes(k))) tags.add(tag);
    }
    if ((report?.dropped || []).length > 0) tags.add('dropper');
    if ((report?.network?.http || []).length > 0) tags.add('network');
    return Array.from(tags).slice(0, 8);
}

const autoEnrichInflight = new Set();
async function triggerAutoEnrich(taskId, userId) {
    const key = `${userId}::${taskId}`;
    if (autoEnrichInflight.has(key)) return;
    autoEnrichInflight.add(key);
    try {
        // Skip if already enriched
        const all = await storeListSubmissions(userId);
        const sub = all.find(s => String(s.taskId) === String(taskId));
        if (!sub) return;
        if (sub.verdict && sub.verdict !== 'unknown' && Array.isArray(sub.tags) && sub.tags.length) return;

        const report = await fetchCapeReportJson(taskId);
        const { verdict, verdictNote } = deriveVerdict(report);
        const tags = deriveTags(report);
        await storeUpdateSubmission(taskId, userId, { verdict, verdictNote, tags });
        await writeLog('tasks.log', { type: 'auto_enrich', user: userId, taskId, verdict, tags });
    } catch (e) {
        // Quiet failure (report may not be ready yet)
    } finally {
        autoEnrichInflight.delete(key);
    }
}

async function getReportSummary(taskId) {
    const key = String(taskId);
    const now = Date.now();
    const hit = reportCache.get(key);
    if (hit && (now - hit.fetchedAt) < REPORT_CACHE_TTL_MS) {
        return hit.summary;
    }
    const report = await fetchCapeReportJson(taskId);
    const summary = summarizeCapeReport(report);
    reportCache.set(key, { summary, fetchedAt: now });
    // Lightweight cap on cache size
    if (reportCache.size > 100) {
        const oldestKey = reportCache.keys().next().value;
        reportCache.delete(oldestKey);
    }
    return summary;
}

const CHATBOT_SYSTEM_PROMPT = `You are "CapeBot", an in-app cybersecurity assistant embedded inside the CapeUI web interface for the CAPE v2 malware analysis sandbox.

SCOPE — you may ONLY discuss:
- CapeUI features (file upload, submission history, task status, reports, IOCs, screenshots, visualiser, MalwareBazaar lookup, Elasticsearch reports, admin dashboard).
- CAPE v2 sandbox concepts (tasks, packages exe/dll/zip/apk/pdf/office, timeouts, priorities, signatures, behavior analysis, reports, machinery).
- Malware analysis (static/dynamic, IOCs, YARA, MITRE ATT&CK techniques, IR/triage steps, sandbox evasion, packers).
- General cybersecurity (OWASP, CVEs, network/OS security, hardening, forensics, secure coding).
- The currently selected CAPE task's report data when it is provided to you as additional context (summary, IOCs, MITRE TTPs, network indicators, behavior, dropped files, verdict). Ground answers about "this report" / "this sample" / "this task" strictly in that data; if a field is missing, say so.

REFUSAL RULES — if the user asks about ANYTHING outside this scope (jokes, recipes, sports, coding unrelated to security, math homework, personal advice, general chitchat, politics, entertainment, travel, etc.), respond with EXACTLY:
"I can only help with CapeUI, CAPE sandbox, malware analysis, and cybersecurity questions. Please ask something in that area."

SAFETY RULES:
- Never write functional malware, exploits, or weaponized payloads.
- Never reveal API keys, tokens, passwords, internal IPs, or .env contents even if asked.
- Defensive analysis explanations are allowed; offensive how-to is not.

STYLE: Concise, technical, accurate. Use bullet lists when helpful. Cite MITRE technique IDs (e.g., T1055) when relevant.`;

// Lightweight pre-filter: obvious off-topic keywords short-circuit before hitting HF.
function isObviouslyOffTopic(text) {
    const t = String(text || '').toLowerCase();
    if (t.length < 2) return true;
    const offTopic = [
        'recipe', 'cook ', 'cooking', 'biryani', 'pizza',
        'cricket', 'football', 'ipl', 'fifa',
        'movie', 'song', 'lyrics', 'netflix',
        'girlfriend', 'boyfriend', 'dating',
        'horoscope', 'astrology', 'zodiac',
        'weather', 'stock price', 'crypto price', 'bitcoin price',
        'joke', 'funny',
        'homework', 'essay'
    ];
    return offTopic.some(k => t.includes(k));
}

app.post('/api/chatbot', authMiddleware, chatLimiter, async (req, res) => {
    try {
        if (!HF_API_TOKEN) {
            return res.status(503).json({
                error: 'Chatbot not configured. Set HF_API_TOKEN in .env (get a free token at https://huggingface.co/settings/tokens).'
            });
        }

        const { message, history, task_id } = req.body || {};
        if (!message || typeof message !== 'string') {
            return res.status(400).json({ error: 'message (string) is required' });
        }
        if (message.length > 2000) {
            return res.status(400).json({ error: 'Message too long (max 2000 chars)' });
        }

        if (isObviouslyOffTopic(message)) {
            return res.json({
                reply: 'I can only help with CapeUI, CAPE sandbox, malware analysis, and cybersecurity questions. Please ask something in that area.',
                offTopic: true
            });
        }

        // Build OpenAI-style chat messages. Trim history to last 8 exchanges.
        const safeHistory = Array.isArray(history)
            ? history
                .filter(m => m && typeof m.role === 'string' && typeof m.content === 'string')
                .filter(m => m.role === 'user' || m.role === 'assistant')
                .slice(-8)
                .map(m => ({ role: m.role, content: String(m.content).slice(0, 2000) }))
            : [];

        // If task_id provided and valid, fetch+inject the CAPE report summary as context.
        let reportContextMsg = null;
        let reportLoaded = false;
        let reportError = null;
        if (task_id !== undefined && task_id !== null && /^\d+$/.test(String(task_id))) {
            try {
                const summary = await getReportSummary(String(task_id));
                reportContextMsg = {
                    role: 'system',
                    content:
                        `The user is currently viewing CAPE sandbox task #${task_id}. Below is a structured summary of that task's analysis report. When the user asks about "this report", "this sample", "the file", "summary", "IOCs", "MITRE", "verdict", "network", "behavior", etc., ground your answer in the data below. Cite specific values (hashes, IPs, domains, technique IDs) where useful. If a piece of data is missing from the summary, say so honestly.

--- REPORT SUMMARY (task #${task_id}) ---
${summary}
--- END REPORT SUMMARY ---`
                };
                reportLoaded = true;
            } catch (e) {
                reportError = e.response?.status === 404
                    ? `No report yet for task #${task_id} (analysis may still be running or this task has no JSON report).`
                    : `Could not load report for task #${task_id}: ${e.message}`;
            }
        }

        const messages = [
            { role: 'system', content: CHATBOT_SYSTEM_PROMPT },
            ...(reportContextMsg ? [reportContextMsg] : []),
            ...(reportError ? [{ role: 'system', content: `Note: ${reportError}` }] : []),
            ...safeHistory,
            { role: 'user', content: message }
        ];

        const payload = {
            model: HF_MODEL,
            messages,
            max_tokens: 512,
            temperature: 0.3,
            top_p: 0.9,
            stream: false
        };

        const hfResp = await axios.post(HF_API_URL, payload, {
            headers: {
                'Authorization': `Bearer ${HF_API_TOKEN}`,
                'Content-Type': 'application/json'
            },
            timeout: 45000
        });

        const reply = hfResp.data?.choices?.[0]?.message?.content?.trim()
            || 'Sorry, I could not generate a response.';

        await writeLog('chatbot.log', {
            type: 'chat',
            user: userFromReq(req),
            ip: req.ip,
            qLen: message.length,
            aLen: reply.length,
            model: HF_MODEL,
            taskId: task_id || null,
            reportLoaded
        });

        return res.json({
            reply,
            model: HF_MODEL,
            taskId: task_id || null,
            reportLoaded,
            reportError
        });
    } catch (err) {
        const status = err.response?.status || 0;
        const body = await readHfErrorBody(err).catch(() => null);
        const detail = body || err.message;
        console.error('Chatbot error:', status, detail);
        await writeLog('chatbot.log', {
            type: 'chat_error',
            user: userFromReq(req),
            ip: req.ip,
            status,
            error: String(detail).slice(0, 500)
        });
        const mapped = mapHfError(status, detail);
        return res.status(mapped.status).json({ error: mapped.message });
    }
});

// --- Streaming chatbot (Server-Sent Events) ---
// Translate any axios error from Hugging Face into a clean { status, message }
// pair the client can display verbatim. Used by both the streaming and the
// non-streaming chatbot endpoints so the user sees the same human-readable
// reason regardless of transport.
async function readHfErrorBody(err) {
    // For streaming responses, error.response.data may be a stream — drain it.
    const data = err?.response?.data;
    if (!data) return null;
    if (typeof data === 'string') return data;
    if (typeof data === 'object' && !data.on) {
        return data.error?.message || data.error || data.message || JSON.stringify(data).slice(0, 400);
    }
    if (data.on) {
        try {
            const chunks = [];
            for await (const c of data) chunks.push(c);
            const text = Buffer.concat(chunks.map(c => Buffer.isBuffer(c) ? c : Buffer.from(c))).toString('utf8');
            try {
                const j = JSON.parse(text);
                return j.error?.message || j.error || j.message || text.slice(0, 400);
            } catch (_) { return text.slice(0, 400); }
        } catch (_) { return null; }
    }
    return null;
}

function mapHfError(status, body) {
    const txt = (body || '').toString().toLowerCase();
    if (status === 400) {
        if (txt.includes('input') && (txt.includes('long') || txt.includes('limit') || txt.includes('token')))
            return { status: 413, message: 'Your message + report context is too long for the chosen model. Open a new chat or try without a task selected.' };
        if (txt.includes('model') && (txt.includes('not') || txt.includes('unknown') || txt.includes('unsupported')))
            return { status: 502, message: `Model "${HF_MODEL}" is not available on Hugging Face Inference Providers. Set HF_MODEL in .env to a supported chat model (e.g. meta-llama/Llama-3.1-8B-Instruct).` };
        return { status: 502, message: `Hugging Face rejected the request (${body || 'bad request'}).` };
    }
    if (status === 401 || status === 403) return { status: 502, message: 'Hugging Face auth failed. Check that HF_API_TOKEN in .env is valid and has read access.' };
    if (status === 404) return { status: 502, message: `Model "${HF_MODEL}" not found on Hugging Face Inference Providers. Update HF_MODEL in .env.` };
    if (status === 429) return { status: 429, message: 'Hugging Face rate limit hit. Try again in a minute.' };
    if (status === 503) return { status: 503, message: 'The model is loading on Hugging Face. Try again in ~20 seconds.' };
    return { status: 502, message: `Chatbot upstream error: ${body || (status ? 'HTTP ' + status : 'unknown')}` };
}

app.post('/api/chatbot/stream', authMiddleware, chatLimiter, async (req, res) => {
    try {
        if (!HF_API_TOKEN) return res.status(503).json({ error: 'Chatbot not configured. Set HF_API_TOKEN in .env.' });
        const { message, history, task_id } = req.body || {};
        if (!message || typeof message !== 'string') return res.status(400).json({ error: 'message required' });
        if (message.length > 2000) return res.status(400).json({ error: 'message too long' });

        if (isObviouslyOffTopic(message)) {
            res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive' });
            res.write(`data: ${JSON.stringify({ type: 'token', text: 'I can only help with CapeUI, CAPE sandbox, malware analysis, and cybersecurity questions. Please ask something in that area.' })}\n\n`);
            res.write(`data: ${JSON.stringify({ type: 'done' })}\n\n`);
            return res.end();
        }

        const safeHistory = Array.isArray(history)
            ? history.filter(m => m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string')
                .slice(-8).map(m => ({ role: m.role, content: String(m.content).slice(0, 2000) }))
            : [];

        let reportContextMsg = null;
        let reportError = null;
        if (task_id !== undefined && task_id !== null && /^\d+$/.test(String(task_id))) {
            try {
                const summary = await getReportSummary(String(task_id));
                reportContextMsg = {
                    role: 'system',
                    content: `The user is currently viewing CAPE sandbox task #${task_id}. Below is a structured summary of that task's report. Ground answers about "this report" / "this sample" in this data.\n\n--- REPORT SUMMARY (task #${task_id}) ---\n${summary}\n--- END ---`
                };
            } catch (e) {
                reportError = e.response?.status === 404
                    ? `No report yet for task #${task_id}.`
                    : `Could not load report for task #${task_id}.`;
            }
        }

        const messages = [
            { role: 'system', content: CHATBOT_SYSTEM_PROMPT },
            ...(reportContextMsg ? [reportContextMsg] : []),
            ...(reportError ? [{ role: 'system', content: 'Note: ' + reportError }] : []),
            ...safeHistory,
            { role: 'user', content: message }
        ];

        // Forward streaming request to HF FIRST. We deliberately do NOT flush
        // SSE headers yet — if HF responds with a 4xx/5xx, we want to be able
        // to return a proper HTTP status (and a readable error body) to the
        // client instead of being locked into a 200 SSE response.
        let hfResp;
        try {
            hfResp = await axios.post(HF_API_URL,
                { model: HF_MODEL, messages, max_tokens: 512, temperature: 0.3, top_p: 0.9, stream: true },
                {
                    headers: { 'Authorization': `Bearer ${HF_API_TOKEN}`, 'Content-Type': 'application/json' },
                    responseType: 'stream',
                    timeout: 60000,
                    // Only treat 2xx as success — without this, streaming responses
                    // with 4xx bodies would slip through and break SSE parsing.
                    validateStatus: s => s >= 200 && s < 300
                }
            );
        } catch (hfErr) {
            const status = hfErr.response?.status || 0;
            const body = await readHfErrorBody(hfErr);
            const mapped = mapHfError(status, body);
            await writeLog('chatbot.log', {
                type: 'chat_stream_upstream_error',
                user: userFromReq(req), ip: req.ip,
                hfStatus: status, hfBody: (body || '').toString().slice(0, 400),
                mappedStatus: mapped.status
            });
            return res.status(mapped.status).json({ error: mapped.message });
        }

        // HF accepted the request; only NOW commit to SSE response.
        res.set({
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache, no-transform',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no'
        });
        res.flushHeaders?.();

        if (reportError) {
            res.write(`data: ${JSON.stringify({ type: 'meta', reportError })}\n\n`);
        }

        let buf = '';
        let totalLen = 0;
        let finished = false; // guards against writing after the stream is closed
        const finish = (extraEvent) => {
            if (finished) return;
            finished = true;
            try {
                if (extraEvent) res.write(`data: ${JSON.stringify(extraEvent)}\n\n`);
                res.write(`data: ${JSON.stringify({ type: 'done' })}\n\n`);
                res.end();
            } catch (_) { /* socket already closed by client */ }
            writeLog('chatbot.log', { type: 'chat_stream', user: userFromReq(req), aLen: totalLen, taskId: task_id || null }).catch(() => { });
        };

        hfResp.data.on('data', chunk => {
            if (finished) return;
            buf += chunk.toString('utf8');
            const lines = buf.split('\n');
            buf = lines.pop() || '';
            for (const ln of lines) {
                const t = ln.trim();
                if (!t || !t.startsWith('data:')) continue;
                const payload = t.slice(5).trim();
                if (payload === '[DONE]') { finish(); return; }
                try {
                    const obj = JSON.parse(payload);
                    const tok = obj?.choices?.[0]?.delta?.content || obj?.choices?.[0]?.message?.content || '';
                    if (tok) {
                        totalLen += tok.length;
                        try { res.write(`data: ${JSON.stringify({ type: 'token', text: tok })}\n\n`); } catch (_) { finished = true; }
                    }
                } catch (_) { /* swallow malformed chunk */ }
            }
        });
        hfResp.data.on('end', () => finish());
        hfResp.data.on('error', err => {
            // Never leak raw axios messages like "Request failed with status code 400"
            // to the chat panel. Map through the same helper as the inner catch block.
            const status = err?.response?.status || 0;
            const mapped = mapHfError(status, err?.message || '');
            finish({ type: 'error', error: mapped.message });
        });
        // Client may close the tab mid-stream — abort the upstream so we don't
        // keep writing to a dead socket.
        req.on('close', () => { finished = true; try { hfResp.data.destroy(); } catch (_) { } });
    } catch (error) {
        const status = error.response?.status || 0;
        const body = await readHfErrorBody(error).catch(() => null);
        const mapped = mapHfError(status, body || error.message);
        if (!res.headersSent) {
            return res.status(mapped.status).json({ error: mapped.message });
        }
        try {
            res.write(`data: ${JSON.stringify({ type: 'error', error: mapped.message })}\n\n`);
            res.end();
        } catch (_) { }
    }
});

// --- Health Check ---
app.get('/api/health', async (req, res) => {
    let capeOk = false;
    try {
        const r = await axios.get(`${CAPE_API_BASE}/apiv2/cuckoo/status/`, { timeout: 3000 }).catch(async () => {
            return await axios.get(CAPE_API_BASE, { timeout: 3000 });
        });
        capeOk = !!r;
    } catch (_) { capeOk = false; }
    res.json({
        ok: true,
        services: {
            db: { ok: mongoConnected, mode: mongoConnected ? 'mongodb' : 'in-memory-fallback' },
            cape: { ok: capeOk, mode: 'live', base: CAPE_API_BASE },
            chatbot: { ok: !!HF_API_TOKEN, model: HF_MODEL }
        },
        ts: new Date().toISOString()
    });
});

// --- Structured report data for visualizations (MITRE matrix, network, etc.) ---
app.get('/api/task/:taskId/structured', authMiddleware, async (req, res) => {
    try {
        const { taskId } = req.params;
        if (!/^\d+$/.test(taskId)) return res.status(400).json({ error: 'Invalid Task ID' });
        const report = await fetchCapeReportJson(taskId);

        // MITRE matrix data
        const ttps = report.ttps || report.mitre || [];
        const techniques = (Array.isArray(ttps) ? ttps : []).map(t => ({
            id: t.t_id || t.technique_id || t.id || '',
            name: t.name || t.technique || t.description || '',
            tactics: Array.isArray(t.tactics) ? t.tactics : (t.tactic ? [t.tactic] : [])
        })).filter(t => t.id);

        // Network IOCs
        const network = {
            hosts: (report.network?.hosts || []).map(h => typeof h === 'string' ? h : (h.ip || h.address || '')).filter(Boolean),
            dns: (report.network?.dns || []).map(d => ({
                request: d.request || d.hostname || d.query || '',
                answers: Array.isArray(d.answers) ? d.answers.map(a => a.data || a) : []
            })),
            http: (report.network?.http || []).map(h => ({
                method: h.method || 'GET',
                uri: h.uri || h.url || h.host || ''
            }))
        };

        // Verdict + tags (compute fresh)
        const v = deriveVerdict(report);
        const tags = deriveTags(report);

        // Quick stats
        const stats = {
            signatures: (report.signatures || []).length,
            ttps: techniques.length,
            dropped: (report.dropped || []).length,
            processes: (report.behavior?.processes || []).length,
            hosts: network.hosts.length,
            dns: network.dns.length,
            http: network.http.length,
            malscore: report.malscore ?? report.score ?? null
        };

        res.json({
            taskId,
            verdict: v.verdict,
            verdictNote: v.verdictNote,
            tags,
            target: report.target?.file || report.target || {},
            info: report.info || {},
            techniques,
            network,
            signatures: (report.signatures || []).slice(0, 25).map(s => ({
                name: s.name || s.short_description, severity: s.severity ?? 0, confidence: s.confidence ?? 0,
                description: s.description || ''
            })),
            stats
        });
    } catch (error) {
        const status = error.response?.status === 404 ? 404 : 500;
        return res.status(status).json({ error: status === 404 ? 'Report not ready yet' : 'Failed to load report' });
    }
});

// --- IOC export (CSV / STIX-lite JSON) ---
app.get('/api/task/:taskId/iocs.:format', authMiddleware, async (req, res) => {
    try {
        const { taskId, format } = req.params;
        if (!/^\d+$/.test(taskId)) return res.status(400).json({ error: 'Invalid Task ID' });
        if (!['csv', 'json'].includes(format)) return res.status(400).json({ error: 'format must be csv or json' });

        const report = await fetchCapeReportJson(taskId);
        const file = report?.target?.file || {};
        const rows = [];
        const push = (type, value, source) => { if (value) rows.push({ type, value: String(value), source }); };

        push('sha256', file.sha256, 'target_file');
        push('sha1', file.sha1, 'target_file');
        push('md5', file.md5, 'target_file');
        push('filename', file.name, 'target_file');

        for (const d of (report.dropped || [])) {
            push('dropped_sha256', d.sha256, 'dropped');
            push('dropped_filename', d.name, 'dropped');
        }
        for (const h of (report.network?.hosts || [])) {
            push('ip', typeof h === 'string' ? h : h.ip, 'network_hosts');
        }
        for (const d of (report.network?.dns || [])) {
            push('domain', d.request || d.hostname, 'network_dns');
            for (const a of (d.answers || [])) push('ip', a.data || a, 'network_dns_answer');
        }
        for (const h of (report.network?.http || [])) {
            push('url', h.uri || h.url, 'network_http');
        }
        for (const m of (report.behavior?.summary?.mutexes || [])) push('mutex', m, 'behavior');
        for (const r of (report.behavior?.summary?.write_keys || [])) push('regkey', r, 'behavior');

        if (format === 'csv') {
            res.set('Content-Type', 'text/csv; charset=utf-8');
            res.set('Content-Disposition', `attachment; filename="iocs_${taskId}.csv"`);
            const esc = v => `"${String(v).replace(/"/g, '""')}"`;
            const out = ['type,value,source', ...rows.map(r => [r.type, r.value, r.source].map(esc).join(','))].join('\n');
            return res.send(out);
        } else {
            res.set('Content-Type', 'application/json');
            res.set('Content-Disposition', `attachment; filename="iocs_${taskId}.json"`);
            return res.json({ taskId, count: rows.length, generated: new Date().toISOString(), iocs: rows });
        }
    } catch (error) {
        const status = error.response?.status === 404 ? 404 : 500;
        return res.status(status).json({ error: status === 404 ? 'Report not ready yet' : 'Failed to export IOCs' });
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

