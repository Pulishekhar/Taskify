require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const http = require('http');
const { Server } = require('socket.io');
const multer = require('multer');
const path = require('path');
const nodemailer = require('nodemailer');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: process.env.FRONTEND_URL || "http://localhost:3000",
        methods: ["GET", "POST", "PUT", "DELETE"],
        allowedHeaders: ["Content-Type", "Authorization"]
    }
});

// Middleware
app.use(cors({
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Database Pool Configuration
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
        console.log(`📢 User ${userId} joined their room`);
    });

    socket.on("disconnect", () => {
        console.log(`❌ User disconnected: ${socket.id}`);
    });
});

// Enhanced Email Configuration
const transporter = nodemailer.createTransport({
    service: "gmail",
    host: "smtp.gmail.com",
    port: 587,
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    tls: {
        ciphers: 'SSLv3',
        minVersion: 'TLSv1.2',
        rejectUnauthorized: process.env.NODE_ENV === 'production'
    },
    logger: true,
    debug: process.env.NODE_ENV !== 'production'
});

// Verify SMTP connection on startup
transporter.verify(function(error) {
    if (error) {
        console.error('❌ SMTP Connection Failed:', error);
    } else {
        console.log('✅ SMTP Server Ready');
    }
});

// Auth Middleware
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    
    if (!token) return res.status(401).json({ error: "No token provided" });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const [users] = await pool.query("SELECT id FROM users WHERE id = ?", [decoded.id]);
        if (!users.length) return res.status(403).json({ error: "User not found" });
        
        req.user = decoded;
        next();
    } catch (err) {
        res.status(403).json({ error: "Invalid token" });
    }
};

// File Upload Configuration
const storage = multer.diskStorage({
    destination: "./uploads/",
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});
const upload = multer({ 
    storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Only JPEG, PNG, and PDF files are allowed'));
        }
    }
});

// ==================== ROUTES ====================

// 1. USER AUTHENTICATION
app.post("/api/register", async (req, res) => {
    try {
        const { name, email, password } = req.body;
        
        // Validation
        if (!name || !email || !password) {
            return res.status(400).json({ error: "All fields are required" });
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ error: "Invalid email format" });
        }
        if (password.length < 8) {
            return res.status(400).json({ error: "Password must be at least 8 characters" });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const [result] = await pool.execute(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            [name, email, hashedPassword]
        );

        res.status(201).json({ 
            message: "User registered successfully",
            userId: result.insertId 
        });
    } catch (error) {
        console.error("Registration Error:", error);
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: "Email already exists" });
        }
        res.status(500).json({ error: "Registration failed" });
    }
});

app.post("/api/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: "Email and password are required" });
        }

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
        res.status(500).json({ error: "Login failed" });
    }
});

// 2. PROJECT ROUTES
app.post("/api/projects", authenticateToken, async (req, res) => {
    try {
        const { name } = req.body;
        if (!name) {
            return res.status(400).json({ error: "Project name is required" });
        }

        const [result] = await pool.execute(
            "INSERT INTO projects (name, user_id) VALUES (?, ?)",
            [name, req.user.id]
        );

        const [project] = await pool.execute(
            "SELECT * FROM projects WHERE id = ?",
            [result.insertId]
        );

        io.emit("projectCreated", project[0]);
        res.status(201).json(project[0]);
    } catch (error) {
        console.error("Project Error:", error);
        res.status(500).json({ error: "Failed to create project" });
    }
});

app.get("/api/projects", authenticateToken, async (req, res) => {
    try {
        const [projects] = await pool.execute(
            "SELECT * FROM projects WHERE user_id = ?",
            [req.user.id]
        );
        res.json(projects);
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch projects" });
    }
});

// 3. TASK ROUTES
app.post("/api/tasks", authenticateToken, async (req, res) => {
    try {
        // Required fields validation
        const { title, project_id } = req.body;
        if (!title || !project_id) {
            return res.status(400).json({ 
                error: "Title and project_id are required" 
            });
        }

        // Set defaults for optional fields
        const taskData = {
            title: title,
            description: req.body.description || null,
            project_id: project_id,
            status: 'todo',
            created_by: req.user.id,
            assigned_to: req.body.assigned_to || null,
            due_date: req.body.due_date || null
        };

        // Verify project exists
        const [project] = await pool.execute(
            "SELECT id FROM projects WHERE id = ? AND user_id = ?",
            [taskData.project_id, taskData.created_by]
        );
        
        if (!project.length) {
            return res.status(404).json({ error: "Project not found or access denied" });
        }

        // Insert task
        const [result] = await pool.execute(
            `INSERT INTO tasks 
             (title, description, project_id, status, created_by, assigned_to, due_date) 
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                taskData.title,
                taskData.description,
                taskData.project_id,
                taskData.status,
                taskData.created_by,
                taskData.assigned_to,
                taskData.due_date
            ]
        );

        // Get the created task with assignee info
        const [task] = await pool.execute(
            `SELECT t.*, u.name as assignee_name 
             FROM tasks t
             LEFT JOIN users u ON t.assigned_to = u.id
             WHERE t.id = ?`,
            [result.insertId]
        );

        // Send email notification if assigned to someone else
        if (taskData.assigned_to && taskData.assigned_to !== taskData.created_by) {
            await sendTaskAssignmentEmail(
                taskData.assigned_to,
                taskData.title,
                taskData.description,
                taskData.due_date,
                taskData.created_by
            );
        }

        io.emit("taskCreated", task[0]);
        res.status(201).json(task[0]);

    } catch (error) {
        console.error("Full Task Creation Error:", {
            message: error.message,
            stack: error.stack,
            body: req.body
        });
        res.status(500).json({ 
            error: "Failed to create task",
            details: process.env.NODE_ENV === 'development' ? error.message : null
        });
    }
});

// Email Notification Function
async function sendTaskAssignmentEmail(assigneeId, title, description, dueDate, creatorId) {
    try {
        // Get assignee details
        const [assignee] = await pool.execute(
            "SELECT email, name FROM users WHERE id = ?", 
            [assigneeId]
        );

        // Get creator details
        const [creator] = await pool.execute(
            "SELECT name FROM users WHERE id = ?",
            [creatorId]
        );

        if (!assignee.length) {
            console.warn(`Assignee ${assigneeId} not found`);
            return;
        }

        // Prepare email
        const mailOptions = {
            from: `"Taskify" <${process.env.EMAIL_USER}>`,
            to: assignee[0].email,
            subject: `New Task: ${title}`,
            html: `
                <div style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px;">
                    <h2 style="color: #2563eb;">New Task Assignment</h2>
                    <p>Hello ${assignee[0].name},</p>
                    <p>${creator[0]?.name || 'A team member'} has assigned you a new task:</p>
                    
                    <div style="background: #f3f4f6; padding: 15px; border-radius: 8px; margin: 15px 0;">
                        <h3 style="margin-top: 0;">${title}</h3>
                        ${description ? `<p>${description}</p>` : ''}
                        ${dueDate ? `<p><strong>Due Date:</strong> ${new Date(dueDate).toLocaleDateString()}</p>` : ''}
                    </div>

                    <p>
                        <a href="${process.env.FRONTEND_URL}/tasks" 
                           style="background: #2563eb; color: white; padding: 10px 15px; text-decoration: none; border-radius: 5px;">
                            View Task in Taskify
                        </a>
                    </p>
                </div>
            `
        };

        // Send email
        const info = await transporter.sendMail(mailOptions);
        console.log(`📧 Email notification sent to ${assignee[0].email}`, info.messageId);

    } catch (error) {
        console.error("Email Notification Error:", {
            assigneeId,
            error: error.message,
            stack: error.stack
        });
    }
}

// Get all tasks for a project
app.get("/api/projects/:id/tasks", authenticateToken, async (req, res) => {
    try {
        const [tasks] = await pool.execute(
            `SELECT t.*, u.name as assignee_name 
             FROM tasks t
             LEFT JOIN users u ON t.assigned_to = u.id
             WHERE t.project_id = ?`,
            [req.params.id]
        );
        res.json(tasks);
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch tasks" });
    }
});

// Update task status
app.put("/api/tasks/:id/status", authenticateToken, async (req, res) => {
    try {
        const { status } = req.body;
        if (!status || !['todo', 'in_progress', 'done'].includes(status)) {
            return res.status(400).json({ error: "Invalid status" });
        }

        const [result] = await pool.execute(
            "UPDATE tasks SET status = ? WHERE id = ? AND created_by = ?",
            [status, req.params.id, req.user.id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Task not found or access denied" });
        }

        const [task] = await pool.execute(
            "SELECT * FROM tasks WHERE id = ?",
            [req.params.id]
        );

        io.emit("taskUpdated", task[0]);
        res.json(task[0]);
    } catch (error) {
        res.status(500).json({ error: "Failed to update task" });
    }
});

// 4. COMMENT ROUTES
app.post("/api/tasks/:id/comments", authenticateToken, async (req, res) => {
    try {
        const { comment } = req.body;
        if (!comment) {
            return res.status(400).json({ error: "Comment cannot be empty" });
        }

        const [result] = await pool.execute(
            "INSERT INTO comments (task_id, user_id, comment) VALUES (?, ?, ?)",
            [req.params.id, req.user.id, comment]
        );

        const [newComment] = await pool.execute(
            `SELECT c.*, u.name as user_name 
             FROM comments c
             JOIN users u ON c.user_id = u.id
             WHERE c.id = ?`,
            [result.insertId]
        );

        io.emit("commentAdded", {
            taskId: req.params.id,
            comment: newComment[0]
        });

        res.status(201).json(newComment[0]);
    } catch (error) {
        res.status(500).json({ error: "Failed to add comment" });
    }
});

app.get("/api/tasks/:id/comments", authenticateToken, async (req, res) => {
    try {
        const [comments] = await pool.execute(
            `SELECT c.*, u.name as user_name 
             FROM comments c
             JOIN users u ON c.user_id = u.id
             WHERE c.task_id = ?
             ORDER BY c.created_at ASC`,
            [req.params.id]
        );
        res.json(comments);
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch comments" });
    }
});

// 5. ATTACHMENT ROUTES
app.post("/api/tasks/:id/attachments", authenticateToken, upload.single("file"), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: "No file uploaded" });
        }

        const [result] = await pool.execute(
            "INSERT INTO attachments (task_id, user_id, file_path) VALUES (?, ?, ?)",
            [req.params.id, req.user.id, req.file.path]
        );

        const [attachment] = await pool.execute(
            `SELECT a.*, u.name as user_name 
             FROM attachments a
             JOIN users u ON a.user_id = u.id
             WHERE a.id = ?`,
            [result.insertId]
        );

        io.emit("attachmentAdded", {
            taskId: req.params.id,
            attachment: attachment[0]
        });

        res.status(201).json(attachment[0]);
    } catch (error) {
        console.error("Attachment Error:", error);
        res.status(500).json({ error: "Failed to upload file" });
    }
});

app.get("/api/tasks/:id/attachments", authenticateToken, async (req, res) => {
    try {
        const [attachments] = await pool.execute(
            `SELECT a.*, u.name as user_name 
             FROM attachments a
             JOIN users u ON a.user_id = u.id
             WHERE a.task_id = ?`,
            [req.params.id]
        );
        res.json(attachments);
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch attachments" });
    }
});

// Test Endpoint
app.get('/test-email', async (req, res) => {
    try {
        const info = await transporter.sendMail({
            to: process.env.EMAIL_USER,
            subject: 'SMTP Test Email',
            text: 'This is a test email from your Taskify server'
        });
        res.json({ success: true, messageId: info.messageId });
    } catch (error) {
        console.error('Email Test Failed:', error);
        res.status(500).json({ error: error.message });
    }
});
// Add this near your other routes (before error handling)
app.get("/", (req, res) => {
    res.json({
      status: "API is running",
      message: "Welcome to Taskify backend!",
      endpoints: {
        tasks: "/api/tasks",
        projects: "/api/projects",
        docs: "https://github.com/your-repo/docs" // Optional
      }
    });
  });

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: "Something went wrong!" });
});

// Start Server
const PORT = process.env.PORT || 5001;
server.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📧 Email service configured for: ${process.env.EMAIL_USER}`);
});