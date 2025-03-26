require("dotenv").config();
const express = require("express");
const mysql = require("mysql2/promise"); // Using promise-based MySQL
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const http = require("http");
const { Server } = require("socket.io");
const multer = require("multer");
const path = require("path");
const nodemailer = require("nodemailer");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*",
    },
});

// Enhanced CORS configuration
app.use(cors({
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MySQL Connection Pool (better performance)
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Verify DB connection
pool.getConnection()
    .then(conn => {
        console.log("✅ Connected to MySQL Database");
        conn.release();
    })
    .catch(err => {
        console.error("❌ MySQL Connection Failed:", err);
    });

// WebSocket Connection
io.on("connection", (socket) => {
    console.log(`🔌 User connected: ${socket.id}`);

    socket.on("joinUserRoom", (userId) => {
        socket.join(`user-${userId}`);
        console.log(`📢 User ${userId} joined their personal task room.`);
    });

    socket.on("disconnect", () => {
        console.log(`❌ User disconnected: ${socket.id}`);
    });
});

// Email Configuration with better security
const transporter = nodemailer.createTransport({
    service: "gmail",
    host: "smtp.gmail.com",
    port: 587,
    secure: false, // true for 465, false for other ports
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
    tls: {
        ciphers: 'SSLv3',
        rejectUnauthorized: false // Only for development
    }
});

// Verify email connection
transporter.verify((error) => {
    if (error) {
        console.error("❌ Email connection verification failed:", error);
    } else {
        console.log("✅ Email server is ready to send messages");
    }
});

// Default Route
app.get("/", (req, res) => {
    res.send("Taskify Backend is Running 🚀");
});

// Enhanced JWT Middleware
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    
    if (!token) {
        return res.status(401).json({ error: "Access denied. No token provided." });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const [users] = await pool.query("SELECT id FROM users WHERE id = ?", [decoded.id]);
        
        if (users.length === 0) {
            return res.status(403).json({ error: "Invalid token - user not found" });
        }
        
        req.user = decoded;
        next();
    } catch (err) {
        console.error("JWT Verification Error:", err);
        return res.status(403).json({ error: "Invalid or expired token." });
    }
};

// Email Notification Endpoint
app.post('/api/notifications/email', async (req, res) => {
    const { to, subject, body } = req.body;

    if (!to || !subject || !body) {
        return res.status(400).json({ error: "Missing required fields" });
    }

    try {
        const mailOptions = {
            from: `"Taskify Team" <${process.env.EMAIL_USER}>`,
            to,
            subject,
            text: body,
            html: `<div style="font-family: Arial, sans-serif; line-height: 1.6;">
                    ${body.replace(/\n/g, '<br>')}
                   </div>`
        };

        const info = await transporter.sendMail(mailOptions);
        console.log("✅ Email sent successfully to:", to);
        res.json({ 
            success: true,
            message: "Email sent successfully",
            messageId: info.messageId 
        });
    } catch (error) {
        console.error("❌ Email sending failed to:", to, "Error:", error.message);
        res.status(500).json({ 
            success: false,
            error: "Failed to send email",
            details: process.env.NODE_ENV === "development" ? error.message : null
        });
    }
});

// User Registration with better validation
app.post("/api/register", async (req, res) => {
    const { name, email, password } = req.body;

    // Basic validation
    if (!name || !email || !password) {
        return res.status(400).json({ error: "All fields are required" });
    }

    // Email format validation
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ error: "Invalid email format" });
    }

    // Password strength check
    if (password.length < 8) {
        return res.status(400).json({ error: "Password must be at least 8 characters" });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 12);
        const [result] = await pool.execute(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            [name, email, hashedPassword]
        );

        res.status(201).json({ 
            success: true,
            message: "User registered successfully",
            userId: result.insertId 
        });
    } catch (error) {
        console.error("Registration Error:", error);
        
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: "Email already exists" });
        }
        
        res.status(500).json({ 
            error: "Registration failed",
            details: process.env.NODE_ENV === "development" ? error.message : null
        });
    }
});

// User Login with rate limiting consideration
app.post("/api/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required" });
    }

    try {
        const [users] = await pool.execute("SELECT * FROM users WHERE email = ?", [email]);
        
        if (users.length === 0) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const user = users[0];
        const isMatch = await bcrypt.compare(password, user.password);
        
        if (!isMatch) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.json({
            success: true,
            message: "Login successful",
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email
            }
        });
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ 
            error: "Login failed",
            details: process.env.NODE_ENV === "development" ? error.message : null
        });
    }
});

// Task Management Endpoints
// ... [Include all your existing task endpoints with pool.execute() instead of db.query()]

// File Upload Configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, path.join(__dirname, 'uploads'));
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only JPEG, PNG, and PDF are allowed.'));
        }
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ 
        error: "Something went wrong!",
        message: process.env.NODE_ENV === "development" ? err.message : null
    });
});

// Start Server
const PORT = process.env.PORT || 5001;
server.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📧 Email service configured for: ${process.env.EMAIL_USER}`);
});