require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Database Connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect((err) => {
    if (err) {
        console.error('Database connection failed: ', err);
        return;
    }
    console.log('Connected to MySQL database.');
});

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ error: 'No token provided' });

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Unauthorized' });
        req.userId = decoded.id;
        next();
    });
};

app.get('/', (req,res) => {
  res.sendFile(path.join(__dirname,"student.html"));
})
// User Registration API
app.post('/register', async (req, res) => {
    const { email, password } = req.body;

    // Check if the user already exists
    db.query('SELECT * FROM students WHERE email = ?', [email], async (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });

        if (results.length > 0) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        // Hash password before storing
        const hashedPassword = await bcrypt.hash(password, 10);
        const query = 'INSERT INTO students (email, password) VALUES (?, ?)';

        db.query(query, [email, hashedPassword], (err, result) => {
            if (err) return res.status(500).json({ error: 'Database error' });

            res.json({ message: 'User registered successfully' });
        });
    });
});

app.get("/home.html", (req,res) => {
  res.sendFile(path.join(__dirname,"home.html"));
})

// User Login API
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const query = 'SELECT * FROM students WHERE email = ?';

    db.query(query, [email], async (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });

        if (results.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = results[0];
        const pass = user.password;
        let isMatch;
        if(pass == password)
        {
          isMatch = true;
        }
        else {
          isMatch = false;
        }

        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        console.log(isMatch);
        res.status(200).json({ message: 'Login successful' });
    });
});

// Protected Route Example
app.get('/profile', verifyToken, (req, res) => {
    res.json({ message: 'Welcome to your profile', userId: req.userId });
});

// Start Server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
