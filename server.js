const express = require("express");
const cors = require('cors');
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const port = 3000;
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware
app.use(cors());
app.use(express.json()); // เพื่อให้แอปยอมรับข้อมูลแบบ json

// เชื่อมต่อ database sqlite
const db = new sqlite3.Database("./myDB.db", (err) => {
  if (err) {
    console.error("Cannot connect database:", err.message);
  } else {
    console.log("Connect database SQLite!!!");
  }
});

// database จำลอง
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name VARCHAR(50) NOT NULL,
      email TEXT NOT NULL,
      password TEXT NOT NULL
    )
  `);

  // เพิ่มข้อมูลจำลอง
//   const stmt = db.prepare(
//     `INSERT INTO users (name, email, password) VALUES (?, ?, ?)`
//   );
//   stmt.run("Waranya", "waranya@example.com", '12345');
//   stmt.run("John Doe", "john@example.com", '123456');
//   stmt.run("Alice", "alice@example.com", '789');
//   stmt.finalize();
//   });
});

// middleware สำหรับ verify jwt
const verify = (req, res, next) => {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if (token == null) {
        return res.status(401)
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(403)
        }
        req.user = user
        next()
    })
}

// routes
app.get("/dashboard", verify, (req, res) => {
  // const email = req.user.email
  res.json({ message: "Welcome to your database" });
});

app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!email) {
      res.status(400).json({ message: "Email is not required!!!" });
    }

    if (!password) {
      res.status(400).json({ message: "Password is not required!!!" });
    }

    const hashPassword = await bcrypt.hash(password, 10);
    const sql = `INSERT INTO users (name, email, password) VALUES (?, ?, ?)`
    
    db.run(sql, [name || "NoName", email, hashPassword], function (err) {
      console.log("DB Error:", err);
      if (err) {
        if (err.errno === 19) {
          return res.status(409).json({ message: "Email already exsits" });
        }
        return res.status(500).json({ message: "Database Error" });
      }
      res
        .status(201)
        .json({ message: "User register success!!", userId: this.lastID });
    });

  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const sql = `SELECT * FROM users WHERE email=?`

    db.get(sql, [email], async (err, user) => {
        if (err) {
            return res.status(500).json({ message: 'Server error'})
        }

        if (!user) {
            return res.status(404).json({ message: 'User not found'})
        }

        const isMatch = await bcrypt.compare(password, user.password)
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid Credentials'})
        }

        const token = jwt.sign({ id: user.id, email: user.email}, JWT_SECRET, { expiresIn: '1h'})
        res.json({ message: 'Login success', token})
    })
})

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
