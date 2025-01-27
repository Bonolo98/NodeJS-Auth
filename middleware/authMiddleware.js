import jwt from 'jsonwebtoken';
import { JWT_SECRET } from '../config/config.js';
import hashPassword from '../utils/hashUtils.js';

const authenticateJWT = (req, res, next) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    return res.status(403).json({ error: "Access denied. No token provided." });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid or expired token." });
    }

    req.user = user;
    next();
  });
};

export default authenticateJWT;
