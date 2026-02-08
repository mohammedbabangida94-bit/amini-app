// =================================================================
// 1. IMPORTS
// =================================================================
const dotenv = require('dotenv');
dotenv.config();
const mongoose = require('mongoose');
const express = require('express');
const cors = require('cors');
const path = require('path');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// ⚠️ CHANGE THIS: Just use the basic require, do not call any 'new' until we fix the constructor
const sendchamp = require('sendchamp');

// =================================================================
// 2. CONFIGURATION
// =================================================================
const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key';
const MONGO_URI = process.env.MONGO_URI;

let sendchampClient;

try {
    // Check if sendchamp is a function (some versions) or has a constructor
    if (typeof sendchamp === 'function') {
        sendchampClient = new sendchamp(process.env.SENDCHAMP_PUBLIC_KEY, 'live');
    } else if (sendchamp.Sendchamp) {
        sendchampClient = new sendchamp.Sendchamp(process.env.SENDCHAMP_PUBLIC_KEY, 'live');
    } else {
        // Fallback to simple object if it's already an instance
        sendchampClient = sendchamp; 
    }
    console.log("✅ Sendchamp initialized as client (not server)");
} catch (err) {
    console.error("❌ Sendchamp initialization failed:", err.message);
}

// =================================================================
// 3. MIDDLEWARE (Order is critical!)
// =================================================================
app.set('trust proxy', 1);

// CORS
const allowedOrigins = [
    'https://amini-app-new.onrender.com',
    'https://amini-frontend-client.vercel.app',
    'https://amini-app.com', 
    'https://www.amini-app.com', 
    'https://amini-frontend-client-8jov8es3r.vercel.app',
    'http://localhost:5500'
];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            return callback(new Error('CORS blocked this origin'), false);
        }
        return callback(null, true);
    },
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true, 
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Global Logger
app.use((req, res, next) => {
    console.log(`[${new Date().toLocaleString()}] ${req.method} ${req.url}`);
    next();
});

// Static Files - Must be BEFORE routes
app.use(express.static(__dirname));

// =================================================================
// 4. DATABASE MODELS
// =================================================================
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    emergencyContacts: [String], 
    firstName: String
});
const User = mongoose.model('User', userSchema);

const reportSchema = new mongoose.Schema({
    userEmail: { type: String, required: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    message: { type: String, required: true },
    location: { latitude: Number, longitude: Number },
    locationUrl: String,
    date: { type: Date, default: Date.now }
});
const Report = mongoose.model('Report', reportSchema);

mongoose.connect(MONGO_URI || 'mongodb://localhost/temp_db')
    .then(() => console.log("MongoDB Connection Successful! 🥳"))
    .catch(err => { console.error("MongoDB Error:", err); process.exit(1); });

// =================================================================
// 5. AUTH MIDDLEWARE
// =================================================================
const authMiddleware = (req, res, next) => {
    const token = req.header('x-auth-token'); 
    if (!token) return res.status(401).json({ message: 'No token, access denied' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET); 
        req.user = decoded.user;
        next(); 
    } catch (err) {
        res.status(401).json({ message: 'Token is not valid' });
    }
};

// =================================================================
// 6. PUBLIC ROUTES
// =================================================================

// Main UX Entry Point
app.get('/', (req, res) => {
    const indexPath = path.join(__dirname, 'index.html');
    res.sendFile(indexPath, (err) => {
        if (err) {
            res.status(404).send("<h1>UX Missing</h1><p>Ensure index.html is in the root folder.</p>");
        }
    });
});

// Health Check
app.get('/status', (req, res) => {
    res.json({ status: 'Live', db: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected' });
});

// User Registration
app.post('/register', [
    body('email', 'Invalid email').isEmail(),
    body('password', 'Min 6 characters').isLength({ min: 6 }),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
        const { email, password } = req.body;
        let user = await User.findOne({ email });
        if (user) return res.status(400).json({ message: 'User already exists' });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        user = new User({ email, password: hashedPassword });
        await user.save();

        const payload = { user: { id: user.id, email: user.email } };
        jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' }, (err, token) => {
            if (err) throw err;
            res.status(201).json({ token });
        });
    } catch (err) {
        res.status(500).json({ message: 'Server error during registration' });
    }
});

// =================================================================
// 7. PROTECTED ROUTES
// =================================================================

app.get('/profile', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json({ user });
    } catch (err) {
        res.status(500).json({ message: 'Error fetching profile' });
    }
});

app.post('/api/report', authMiddleware, async (req, res) => {
    try {
        const { message, location } = req.body;
        const userEmail = req.user.email;
        const locationToUse = location || {};

        const user = await User.findOne({ email: userEmail });
        if (!user) return res.status(404).json({ message: 'User not found' });

        const locationUrl = (locationToUse.latitude && locationToUse.longitude)
            ? `https://www.google.com/maps?q=${locationToUse.latitude},${locationToUse.longitude}`
            : 'Location unavailable';

        const newReport = new Report({
            userEmail,
            user: user._id,
            message: message || "SOS Alert Triggered",
            location: locationToUse,
            locationUrl
        });
        await newReport.save();

        // Sendchamp SMS Logic
        let sendchampClient;
try {
    // This covers all versions of the Sendchamp SDK
    const Sendchamp = require('sendchamp');
    sendchampClient = new Sendchamp({
        publicKey: process.env.SENDCHAMP_PUBLIC_KEY,
        stage: 'live' 
    });
    console.log("✅ Sendchamp initialized successfully!");
} catch (err) {
    console.error("❌ Sendchamp initialization failed:", err.message);
}
        res.json({ message: 'SOS processed', locationUrl });
    } catch (err) {
        res.status(500).json({ message: 'SOS failed', error: err.message });
    }
});

app.get('/api/reports', authMiddleware, async (req, res) => {
    try {
        const reports = await Report.find({ userEmail: req.user.email }).sort({ date: -1 }).limit(10);
        res.json(reports);
    } catch (err) {
        res.status(500).json({ message: 'Log error' });
    }
});

app.put('/api/users/contacts', authMiddleware, async (req, res) => {
    try {
        const { contacts } = req.body;
        const user = await User.findByIdAndUpdate(req.user.id, { $set: { emergencyContacts: contacts } }, { new: true }).select('-password');
        res.json({ message: 'Contacts updated', contacts: user.emergencyContacts });
    } catch (err) {
        res.status(500).json({ message: 'Update error' });
    }
});

app.listen(PORT, () => {
    console.log(`🚀 Amini app running on port ${PORT}`);
    console.log("📁 Current Directory:", __dirname);
    const fs = require('fs');
    console.log("📄 Files present:", fs.readdirSync(__dirname));
    console.log("📂 I am looking for index.html in:", __dirname);
});
// =================================================================
// 8. START
// =================================================================
app.listen(PORT, () => {
    console.log(`🚀 Amini app running on port ${PORT}`);
});