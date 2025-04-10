const express = require('express');
const { signup, login, refreshToken, profile, logout } = require('../controllers/authController');
const authMiddleware = require('../middleware/authMiddleware');

const router = express.Router();

router.post('/signup', signup); 
router.post('/login', login);
router.post('/token', refreshToken);
router.get('/profile', authMiddleware, profile);
router.post('/logout', logout);

module.exports = router;
