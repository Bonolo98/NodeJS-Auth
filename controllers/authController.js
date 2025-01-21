import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import pool from '../config/db.js';
import { JWT_SECRET } from '../config/config.js';
import hashPassword from '../utils/hashUtils.js';  // Correct import for default export

const register = async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: "All fields are required." });
  }

  try {
    const hashedPassword = await hashPassword(password);

    const result = await pool.query(
      "INSERT INTO Users (username, email, password_hash, created_at, updated_at) VALUES ($1, $2, $3, NOW(), NOW()) RETURNING id, username, email, created_at",
      [username, email, hashedPassword]
    );

    res.status(201).json({ message: "User registered successfully.", user: result.rows[0] });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(400).json({ error: "Username or email already exists." });
    }
    console.error(error);
    res.status(500).json({ error: "An error occurred. Please try again later." });
  }
};

const login = async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required." });
  }

  try {
    const result = await pool.query("SELECT * FROM Users WHERE username = $1", [username]);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid username or password." });
    }

    const user = result.rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);

    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid username or password." });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.status(200).json({
      message: "Login successful.",
      token,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "An error occurred. Please try again later." });
  }
};

const profile = async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, username, email FROM Users WHERE id = $1",
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found." });
    }

    res.status(200).json({ user: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "An error occurred. Please try again later." });
  }
};

export { register, login, profile };  // Use named export in ES module
