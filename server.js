// server.js
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error(err));

// User schema
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    wallets: [{ type: String }] // Array of wallet addresses
});

const User = mongoose.model('User', userSchema);

// Register a new user
app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword });
    await user.save();
    res.status(201).send('User registered');
});

// Login user
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
        res.json({ token, wallets: user.wallets });
    } else {
        res.status(401).send('Invalid credentials');
    }
});

// Middleware to authenticate JWT
const authenticateJWT = (req, res, next) => {
    const token = req.headers['authorization'];
    if (token) {
        jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
            if (err) return res.sendStatus(403);
            req.user = user;
            next();
        });
    } else {
        res.sendStatus(401);
    }
};

// Add wallet to user's account
app.post('/api/addWallet', authenticateJWT, async (req, res) => {
    const { walletAddress } = req.body;
    await User.findByIdAndUpdate(req.user.id, { $addToSet: { wallets: walletAddress } });
    res.send('Wallet added');
});

// Get user's wallets
app.get('/api/wallets', authenticateJWT, async (req, res) => {
    const user = await User.findById(req.user.id);
    res.json(user.wallets);
});

// Start the server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
