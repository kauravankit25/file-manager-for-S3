const jwt = require('jsonwebtoken');
const { User } = require('../models');
const crypto = require('crypto');

const algorithm = 'aes-256-cbc';
const ENCRYPTION_SECRET = process.env.GLOBAL_ENCRYPTION_SECRET;
const IV_LENGTH = 16;

async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findByPk(decoded.userId);

    if (user.is_admin) {
      let userId = req.body.userId;
      if (!userId) {
        return res.status(401).json({ error: 'User Id not provided' });
      }
      const loginUser= await User.findByPk(userId);
      if (!loginUser) {
         return res.status(401).json({ error: 'User Id invalid' });
      }
      req.user = loginUser;
    }
    if (!user || user.current_token !== token) {
      return res.status(403).json({ error: 'Unauthorized. Invalid session or user.' });
    }

    req.user = user;
    next();
    return;
  } catch (err) {
    console.error('JWT error:', err);
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token has expired.' });
    } else if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid or malformed token.' });
    } else {
      return res.status(403).json({ error: 'Unauthorized access.' });
    }
  }
}


function decrypt(text) {
  const data = Buffer.from(text, 'base64');
  const iv = data.slice(0, IV_LENGTH);
  const encryptedText = data.slice(IV_LENGTH);
  const decipher = crypto.createDecipheriv(algorithm, Buffer.from(ENCRYPTION_SECRET, 'hex'), iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return JSON.parse(decrypted.toString());
}

function encrypt(obj) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(algorithm, Buffer.from(ENCRYPTION_SECRET, 'hex'), iv);
  let encrypted = cipher.update(JSON.stringify(obj));
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return Buffer.concat([iv, encrypted]).toString('base64');
}

function decryptRequest(req, res, next) {
  if (req.body && req.body.hasOwnProperty('data')) {
    try {
      req.body = decrypt(req.body.data);
    } catch (err) {
      console.log(err)
      return res.status(400).json({ error: 'Failed to decrypt request body' });
    }
  }
  next();
}

function encryptResponse(req, res, next) {
  const originalJson = res.json;
  res.json = function (data) {
    // Only encrypt if the response status code is in the 2xx range
    if (res.statusCode >= 200 && res.statusCode < 300) {
      const encrypted = encrypt(data);
      return originalJson.call(this, { data: encrypted });
    }
    return originalJson.call(this, data);
  };
  next();
}


module.exports = { authenticateToken, decryptRequest,  encryptResponse};