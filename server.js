// server.js - Main server file
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const { pool } = require('./db'); // Database connection setup

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 3600000 } // 1 hour
}));

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Signup endpoint
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    // Input validation
    if (!name || !email || !password) {
      return res.status(400).json({ success: false, message: 'All fields are required' });
    }
    
    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ success: false, message: 'Invalid email format' });
    }
    
    // Password strength validation
    if (password.length < 8) {
      return res.status(400).json({ 
        success: false, 
        message: 'Password must be at least 8 characters long' 
      });
    }
    
    // Check if user already exists
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ success: false, message: 'Email already in use' });
    }
    
    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    // Store user in database
    const newUser = await pool.query(
      'INSERT INTO users (full_name, email, password, created_at) VALUES ($1, $2, $3, NOW()) RETURNING id, full_name, email',
      [name, email, hashedPassword]
    );
    
    // Create session
    req.session.userId = newUser.rows[0].id;
    
    // Return success
    return res.status(201).json({ 
      success: true, 
      message: 'Account created successfully', 
      user: {
        id: newUser.rows[0].id,
        name: newUser.rows[0].full_name,
        email: newUser.rows[0].email
      }
    });
    
  } catch (error) {
    console.error('Signup error:', error);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Social sign-in endpoints
app.get('/auth/google', (req, res) => {
  // In a real implementation, you would redirect to Google OAuth
  res.json({ message: 'Google OAuth endpoint' });
});

app.get('/auth/facebook', (req, res) => {
  // In a real implementation, you would redirect to Facebook OAuth
  res.json({ message: 'Facebook OAuth endpoint' });
});

app.get('/auth/apple', (req, res) => {
  // In a real implementation, you would redirect to Apple Sign In
  res.json({ message: 'Apple Sign In endpoint' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});