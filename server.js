const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const session = require('express-session');
const cors = require('cors');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(cors({
    origin: 'https://antimatter1.onrender.com', // Replace with your frontend URL
    credentials: true
}));

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

pool.on('connect', () => {
    console.log('Successfully connected to the database!');
});

async function createUsersTable() {
    try {
        const client = await pool.connect();
        const query = `
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL
            );
        `;
        await client.query(query);
        client.release();
        console.log('Users table created successfully or already exists.');
    } catch (err) {
        console.error('Error creating users table:', err);
    }
}

createUsersTable();

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true,
        httpOnly: true,
        sameSite: 'none'
    }
}));

app.get('/', (req, res) => {
    res.send('Welcome to the Antimatter API!');
});

app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const client = await pool.connect();
        const query = 'INSERT INTO users(username, email, password_hash) VALUES($1, $2, $3) RETURNING *';
        const values = [username, email, hashedPassword];
        const result = await client.query(query, values);
        client.release();
        res.status(201).json({ message: 'User registered successfully!' });
    } catch (error) {
        if (error.code === '23505') { // Unique violation error
            return res.status(409).json({ error: 'Username or email already exists.' });
        }
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    try {
        const client = await pool.connect();
        const query = 'SELECT * FROM users WHERE username = $1';
        const result = await client.query(query, [username]);
        client.release();

        if (result.rows.length > 0) {
            const user = result.rows[0];
            const passwordMatch = await bcrypt.compare(password, user.password_hash);
            if (passwordMatch) {
                req.session.user = { id: user.id, username: user.username };
                return res.status(200).json({ message: 'Login successful!' });
            }
        }
        res.status(401).json({ error: 'Invalid username or password.' });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ error: 'Could not log out, please try again.' });
        }
        res.status(200).json({ message: 'Logged out successfully.' });
    });
});

// New endpoint to get all users (Admin feature)
app.get('/users', async (req, res) => {
    try {
        if (!req.session.user) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const client = await pool.connect();
        const result = await client.query('SELECT id, username, email FROM users ORDER BY id ASC');
        client.release();
        res.status(200).json(result.rows);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});