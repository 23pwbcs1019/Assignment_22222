import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import Signup from './Schemas/SignupSchema.js';
import { configDotenv } from 'dotenv';
import { compare } from 'bcrypt';

configDotenv();

const app = express();
const PORT = process.env.PORT || 8080;

app.use(express.json());

const mongo_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/hello02';
const JWT_SECRET = process.env.JWT_ACCESS_TOKEN;

if (!JWT_SECRET) {
  console.error('JWT_SECRET is not defined in environment variables');
  process.exit(1);
}

mongoose.connect(mongo_URI)
  .then(() => console.log("MongoDB connected successfully"))
  .catch((error) => console.error(`MongoDB connection error: ${error}`));

// For signUp
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name?.trim() || !email?.trim() || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: "Invalid email format" });
    }

    // Password strength validation
    if (password.length < 8) {
      return res.status(400).json({ message: "Password must be at least 8 characters long" });
    }

    const existingUser = await Signup.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(409).json({ message: "User already registered with this email" });
    }

    const saltRounds = 12; // Increased from 8 for better security
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    const newUser = new Signup({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password: hashedPassword
    });
    
    await newUser.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// For signIn
app.post('/api/signin', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email?.trim() || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const user = await Signup.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      // Use vague message for security
      return res.status(401).json({ message: "User Not Found" });
    }

    const isPasswordValid = await compare(password, user.password);
    console.log("password", password);
    console.log("hashed password", user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { 
        id: user._id,
        email: user.email
      },
      JWT_SECRET,
      { 
        expiresIn: '1h',
        algorithm: 'HS256'
      }
    );

    res.status(200).json({ 
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Signin error:', error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.startsWith('Bearer ') ? 
      authHeader.slice(7) : null;

    if (!token) {
      return res.status(401).json({ message: "Access denied. No token provided." });
    }

    jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] }, (err, decoded) => {
      if (err) {
        if (err.name === 'TokenExpiredError') {
          return res.status(401).json({ message: "Token expired" });
        }
        return res.status(403).json({ message: "Invalid token" });
      }
      req.user = decoded;
      next();
    });
  } catch (error) {
    console.error('Auth middleware error:', error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Protected route example
app.get('/api/protected', authenticateToken, (req, res) => {
  res.status(200).json({
    message: "Access granted",
    user: {
      id: req.user.id,
      email: req.user.email
    }
  });
});

app.listen(PORT, () => console.log(`Server is listening on port ${PORT}`));