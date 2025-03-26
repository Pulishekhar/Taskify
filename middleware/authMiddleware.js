const jwt = require("jsonwebtoken");

const authMiddleware = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(403).json({ error: "No token provided or invalid format" });
    }

    const token = authHeader.split(" ")[1]; // Extract the actual token

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: "Invalid or expired token" });
        req.user = decoded; // Attach decoded token data to req.user
        next();
    });
};

module.exports = authMiddleware;
