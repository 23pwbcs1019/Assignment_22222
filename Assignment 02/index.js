import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { configDotenv } from 'dotenv';
import Signup from './Schemas/SignupSchema.js'; // Ensure the path is correct

// Load environment variables from .env file
configDotenv();

// Server setup
const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_ACCESS_TOKEN;

// Middleware
app.use(express.json());

// JWT verification middleware
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: "No token provided" });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ message: "Invalid token" });
    }
};

// Routes
app.post('/api/signup', async (req, res) => {
    const { name, email, password } = req.body;

    try {
        // Validation
        if (!name || !email || !password) {
            return res.status(400).json({ message: "All fields are required" });
        }

        // Check if the user already exists
        const existingUser = await Signup.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "User already registered with this email" });
        }

        // Hash password and create user
        const saltRounds = 8;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const newUser = new Signup({ name, email, password: hashedPassword });
        await newUser.save();

        // Generate JWT
        const token = jwt.sign(
            { userId: newUser._id, email: newUser.email },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(201).json({
            message: "User registered successfully",
            token: token
        });
    } catch (error) {
        console.log(`Error occurred: ${error}`);
        res.status(500).json({ message: "Error registering user" });
    }
});

app.post("/api/signin", async (req, res) => {
    const { email, password } = req.body;

    try {
        // Validation
        if (!email || !password) {
            return res.status(400).json({ message: "All fields are required" });
        }

        // Find user and verify password
        const user = await Signup.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: "Invalid credentials" });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ message: "Invalid credentials" });
        }

        // Generate JWT
        const token = jwt.sign(
            { userId: user._id, email: user.email },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(200).json({
            message: "Logged in successfully",
            token: token
        });
    } catch (error) {
        console.log(`Error occurred: ${error}`);
        res.status(500).json({ message: "Error signing in. Please try again" });
    }
});

// Protected route
app.get("/api/protected", verifyToken, async (req, res) => {
    try {
        const user = await Signup.findById(req.user.userId).select('-password');
        res.json({
            message: "Access granted to protected route",
            user: user
        });
    } catch (error) {
        console.log(`Error occurred: ${error}`);
        res.status(500).json({ message: "Error accessing protected route" });
    }
});

// MongoDB connection
const mongo_URI = process.env.MONGO_URI;

mongoose.connect(mongo_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => {
        console.log("MongoDB connected successfully");
    })
    .catch((err) => {
        console.error("MongoDB connection error:", err);
    });

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

// Export the Express app for Vercel
export default app;
