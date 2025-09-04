const express = require("express");
const mysql = require("mysql2/promise");
require("dotenv").config();

const app = express();
const port = 8080;

app.get("/", (req, res) => {
  res.send("Backend API is running 🚀");
});

app.get("/products", async (req, res) => {
  try {
    const conn = await mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASS,
      database: process.env.DB_NAME,
    });
    const [rows] = await conn.execute("SELECT '샘플상품' as name, 1000 as price");
    await conn.end();
    res.json(rows);
  } catch (err) {
    res.status(500).send("DB connection error: " + err.message);
  }
});

app.listen(port, () => {
  console.log(`✅ Backend listening on port ${port}`);
});

