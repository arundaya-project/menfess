const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const cors = require("cors");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

// Generate JWT secret jika belum ada
if (!process.env.JWT_SECRET) {
  const jwtSecret = crypto.randomBytes(64).toString("hex");
  let envContent = "";

  try {
    envContent = fs.readFileSync(".env", "utf8");
  } catch (err) {
    // .env file doesn't exist, create it
    envContent = "";
  }

  // Remove existing JWT_SECRET if any
  envContent = envContent.replace(/JWT_SECRET=.*\n?/g, "");

  // Add default admin credentials if not exists
  if (!envContent.includes("ADMIN_USERNAME=")) {
    envContent += "ADMIN_USERNAME=putraasw\n";
  }
  if (!envContent.includes("ADMIN_PASSWORD=")) {
    envContent += "ADMIN_PASSWORD=putrabakwan17\n";
  }

  // Add JWT secret
  envContent += `JWT_SECRET=${jwtSecret}\n`;

  fs.writeFileSync(".env", envContent);
  process.env.JWT_SECRET = jwtSecret;
  process.env.ADMIN_USERNAME = process.env.ADMIN_USERNAME || "putraasw";
  process.env.ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "putrabakwan17";
  console.log("JWT Secret and admin credentials saved to .env");
}

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// Rate limiting untuk menghemat resource server 1GB
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 menit
  max: 100, // limit setiap IP ke 100 requests per windowMs
  message: { error: "Terlalu banyak request, coba lagi nanti" },
});
app.use(limiter);

// Rate limiting khusus untuk menfess creation
const menfessLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 menit
  max: 5, // maksimal 5 menfess per 5 menit per IP
  message: { error: "Terlalu banyak menfess, tunggu 5 menit" },
});

// Add request logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Health check endpoint
app.get("/", (req, res) => {
  res.json({
    message: "Menfess API is running",
    status: "OK",
    timestamp: new Date().toISOString(),
  });
});

// Enhanced audio streaming endpoint
app.get("/api/audio/:filename", (req, res) => {
  const filename = req.params.filename;
  const audioPath = path.join(__dirname, "uploads", "songs", filename);

  console.log(`Audio request: ${filename}`);
  console.log(`Looking for file at: ${audioPath}`);

  // Set CORS headers
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET");
  res.header("Access-Control-Allow-Headers", "Content-Type, Range");

  // Check if file exists
  if (!fs.existsSync(audioPath)) {
    console.log(`Audio file not found: ${audioPath}`);
    return res.status(404).json({ error: "Audio file not found" });
  }

  // Get file stats
  const stat = fs.statSync(audioPath);
  const fileSize = stat.size;
  const range = req.headers.range;

  console.log(`File size: ${fileSize}, Range: ${range}`);

  if (range) {
    // Support for range requests (streaming)
    const parts = range.replace(/bytes=/, "").split("-");
    const start = parseInt(parts[0], 10);
    const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
    const chunksize = end - start + 1;
    const file = fs.createReadStream(audioPath, { start, end });
    const head = {
      "Content-Range": `bytes ${start}-${end}/${fileSize}`,
      "Accept-Ranges": "bytes",
      "Content-Length": chunksize,
      "Content-Type": "audio/mpeg",
      "Cache-Control": "public, max-age=3600",
      "Access-Control-Allow-Origin": "*",
    };
    res.writeHead(206, head);
    file.pipe(res);
  } else {
    // Send entire file
    const head = {
      "Content-Length": fileSize,
      "Content-Type": "audio/mpeg",
      "Accept-Ranges": "bytes",
      "Cache-Control": "public, max-age=3600",
      "Access-Control-Allow-Origin": "*",
    };
    res.writeHead(200, head);
    fs.createReadStream(audioPath).pipe(res);
  }
});

// Enhanced thumbnail serving endpoint with proper CORS headers
app.get("/api/thumbnails/:filename", (req, res) => {
  const filename = decodeURIComponent(req.params.filename);
  const thumbnailPath = path.join(__dirname, "uploads", "thumbnails", filename);

  console.log(`Thumbnail request: ${filename}`);
  console.log(`Looking for file at: ${thumbnailPath}`);

  // Set CORS headers first
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET");
  res.header("Access-Control-Allow-Headers", "Content-Type");

  // Check if file exists
  if (!fs.existsSync(thumbnailPath)) {
    console.log("Thumbnail not found:", thumbnailPath);

    // Try common image formats as fallback
    const commonExtensions = [".jpg", ".jpeg", ".png", ".gif", ".webp"];
    const baseFilename = path.parse(filename).name;

    for (const ext of commonExtensions) {
      const fallbackPath = path.join(
        __dirname,
        "uploads",
        "thumbnails",
        baseFilename + ext
      );
      if (fs.existsSync(fallbackPath)) {
        console.log("Found fallback thumbnail:", fallbackPath);
        return serveThumbnail(fallbackPath, res);
      }
    }

    return res.status(404).json({ error: "Thumbnail not found" });
  }

  serveThumbnail(thumbnailPath, res);
});

function serveThumbnail(filePath, res) {
  try {
    // Get file extension to determine content type
    const ext = path.extname(filePath).toLowerCase();
    let contentType = "image/jpeg"; // default

    switch (ext) {
      case ".png":
        contentType = "image/png";
        break;
      case ".gif":
        contentType = "image/gif";
        break;
      case ".webp":
        contentType = "image/webp";
        break;
      case ".bmp":
        contentType = "image/bmp";
        break;
      case ".svg":
        contentType = "image/svg+xml";
        break;
      default:
        contentType = "image/jpeg";
    }

    // Get file stats for proper headers
    const stats = fs.statSync(filePath);

    // Set proper headers with CORS
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    res.setHeader("Content-Type", contentType);
    res.setHeader("Content-Length", stats.size);
    res.setHeader("Cache-Control", "public, max-age=31536000"); // Cache for 1 year
    res.setHeader("Accept-Ranges", "bytes");
    res.setHeader("Last-Modified", stats.mtime.toUTCString());

    // Stream the file
    const stream = fs.createReadStream(filePath);
    stream.on("error", (error) => {
      console.error("Error streaming thumbnail:", error);
      if (!res.headersSent) {
        res.status(500).json({ error: "Error serving thumbnail" });
      }
    });

    stream.pipe(res);
  } catch (error) {
    console.error("Error in serveThumbnail:", error);
    if (!res.headersSent) {
      res.status(500).json({ error: "Error serving thumbnail" });
    }
  }
}

// Database setup
const db = new sqlite3.Database("./menfess.db", async (err) => {
  if (err) {
    console.error("Error opening database:", err);
    process.exit(1);
  } else {
    console.log("Connected to SQLite database");
    try {
      await initDB();
      startServer();
    } catch (initErr) {
      console.error("Failed to initialize database:", initErr);
      process.exit(1);
    }
  }
});

// Initialize database tables
function initDB() {
  return new Promise((resolve, reject) => {
    // Table untuk admin
    db.run(
      `CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
      (err) => {
        if (err) {
          console.error("Error creating admins table:", err);
          return reject(err);
        }

        // Table untuk lagu
        db.run(
          `CREATE TABLE IF NOT EXISTS songs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          title TEXT NOT NULL,
          artist TEXT,
          filename TEXT UNIQUE NOT NULL,
          thumbnail_filename TEXT,
          thumbnail_url TEXT,
          file_size INTEGER,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`,
          (err) => {
            if (err) {
              console.error("Error creating songs table:", err);
              return reject(err);
            }

            // Table untuk menfess
            db.run(
              `CREATE TABLE IF NOT EXISTS menfess (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_name TEXT NOT NULL,
            receiver_name TEXT NOT NULL,
            message TEXT NOT NULL,
            song_id INTEGER,
            ip_address TEXT,
            likes_count INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (song_id) REFERENCES songs (id)
        )`,
              (err) => {
                if (err) {
                  console.error("Error creating menfess table:", err);
                  return reject(err);
                }

                // Table untuk likes (anonymous users)
                db.run(
                  `CREATE TABLE IF NOT EXISTS menfess_likes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    menfess_id INTEGER NOT NULL,
                    ip_address TEXT NOT NULL,
                    user_fingerprint TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (menfess_id) REFERENCES menfess (id) ON DELETE CASCADE,
                    UNIQUE(menfess_id, ip_address, user_fingerprint)
                )`,
                  (err) => {
                    if (err) {
                      console.error("Error creating menfess_likes table:", err);
                      return reject(err);
                    }

                    // Add likes_count column to existing menfess table if it doesn't exist
                    db.run(
                      `ALTER TABLE menfess ADD COLUMN likes_count INTEGER DEFAULT 0`,
                      (err) => {
                        // Ignore error if column already exists
                        if (err && !err.message.includes("duplicate column")) {
                          console.error(
                            "Error adding likes_count column:",
                            err
                          );
                        }

                        // Create default admin
                        const adminUsername =
                          process.env.ADMIN_USERNAME || "putraasw";
                        const adminPassword =
                          process.env.ADMIN_PASSWORD || "putrabakwan17";
                        const hashedPassword = bcrypt.hashSync(
                          adminPassword,
                          10
                        );

                        db.run(
                          `INSERT OR IGNORE INTO admins (username, password) VALUES (?, ?)`,
                          [adminUsername, hashedPassword],
                          (err) => {
                            if (err) {
                              console.error(
                                "Error creating default admin:",
                                err
                              );
                              return reject(err);
                            }
                            console.log(
                              "Database tables initialized successfully"
                            );
                            console.log(
                              `Default admin created with username: ${adminUsername}`
                            );
                            resolve();
                          }
                        );
                      }
                    );
                  }
                );
              }
            );
          }
        );
      }
    );
  });
}

// Multer setup untuk upload files
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir =
      file.fieldname === "song" ||
      file.fieldname === "audio" ||
      file.fieldname === "file"
        ? "uploads/songs/"
        : "uploads/thumbnails/";
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  },
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB max
  },
  fileFilter: function (req, file, cb) {
    console.log(
      `Processing file: ${file.fieldname} - ${file.originalname} - ${file.mimetype}`
    );

    if (
      file.fieldname === "song" ||
      file.fieldname === "audio" ||
      file.fieldname === "file"
    ) {
      // More lenient audio file validation
      const allowedExtensions = [
        ".mp3",
        ".wav",
        ".m4a",
        ".ogg",
        ".mpeg",
        ".mp4",
        ".aac",
        ".flac",
        ".webm",
      ];
      const allowedMimeTypes = [
        "audio/mpeg",
        "audio/mp3",
        "audio/wav",
        "audio/wave",
        "audio/ogg",
        "audio/mp4",
        "audio/m4a",
        "audio/aac",
        "audio/flac",
        "audio/webm",
        "audio/x-m4a",
        "audio/x-wav",
        "audio/x-mp3",
      ];

      const ext = path.extname(file.originalname).toLowerCase();
      const isValidExtension = allowedExtensions.includes(ext);
      const isValidMimeType = allowedMimeTypes.includes(file.mimetype);

      console.log("Audio validation:", {
        extension: ext,
        mimetype: file.mimetype,
        isValidExtension,
        isValidMimeType,
      });

      if (isValidExtension || isValidMimeType) {
        return cb(null, true);
      } else {
        console.log(
          `Rejected audio file: ${file.originalname} - ${file.mimetype}`
        );
        return cb(
          new Error(
            `File audio tidak valid. Gunakan format: ${allowedExtensions.join(
              ", "
            )}`
          )
        );
      }
    } else if (file.fieldname === "thumbnail") {
      const allowedTypes = /jpeg|jpg|png|gif|webp/;
      const extname = allowedTypes.test(
        path.extname(file.originalname).toLowerCase()
      );
      const mimetype = file.mimetype.includes("image");

      if (mimetype && extname) {
        return cb(null, true);
      } else {
        return cb(
          new Error("Hanya file gambar yang diizinkan (JPG, PNG, GIF, WEBP)")
        );
      }
    } else {
      return cb(new Error(`Field '${file.fieldname}' tidak dikenal`));
    }
  },
});

// Middleware untuk autentikasi admin
const authenticateAdmin = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access token required" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid or expired token" });
    }
    req.user = user;
    next();
  });
};

// Middleware untuk proteksi file lagu (anti-scraping)
const protectSongFiles = (req, res, next) => {
  const referer = req.get("Referer");
  const userAgent = req.get("User-Agent");

  // Cek apakah request dari browser normal dan dari domain yang sama
  if (
    !referer ||
    !userAgent ||
    userAgent.includes("bot") ||
    userAgent.includes("crawler")
  ) {
    return res.status(403).json({ error: "Access denied" });
  }

  next();
};

// ========== PUBLIC ROUTES (USER) ==========

// GET - Mendapatkan semua menfess
app.get("/api/menfess", (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 20;
  const offset = (page - 1) * limit;
  const sortBy = req.query.sort || "recent"; // 'recent', 'trending', 'popular'

  let orderClause = "ORDER BY m.created_at DESC";

  if (sortBy === "trending") {
    // Sort by likes in last 7 days
    orderClause = `ORDER BY (
      SELECT COUNT(*) FROM menfess_likes ml 
      WHERE ml.menfess_id = m.id 
      AND ml.created_at >= datetime('now', '-7 days')
    ) DESC, m.created_at DESC`;
  } else if (sortBy === "popular") {
    orderClause = "ORDER BY m.likes_count DESC, m.created_at DESC";
  }

  const query = `
    SELECT 
      m.*,
      s.id as song_id,
      s.title as song_title, 
      s.artist as song_artist,
      s.filename as song_filename,
      s.thumbnail_filename as song_thumbnail_filename,
      s.thumbnail_url as song_thumbnail_url
    FROM menfess m 
    LEFT JOIN songs s ON m.song_id = s.id 
    ${orderClause}
    LIMIT ? OFFSET ?
  `;

  db.all(query, [limit, offset], (err, rows) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Database error" });
    }

    // Count total untuk pagination
    db.get("SELECT COUNT(*) as total FROM menfess", (err, count) => {
      if (err) {
        console.error("Count error:", err);
        return res.status(500).json({ error: "Database error" });
      }

      const menfessData = rows.map((row) => ({
        id: row.id,
        sender_name: row.sender_name,
        receiver_name: row.receiver_name,
        message: row.message,
        likes_count: row.likes_count || 0,
        song: row.song_id
          ? {
              id: row.song_id,
              title: row.song_title,
              artist: row.song_artist,
              filename: row.song_filename,
              thumbnail_filename: row.song_thumbnail_filename,
              thumbnail_url: row.song_thumbnail_url,
            }
          : null,
        created_at: row.created_at,
      }));

      console.log(`Returning ${menfessData.length} menfess records`);

      res.json({
        data: menfessData,
        pagination: {
          current_page: page,
          total_pages: Math.ceil(count.total / limit),
          total_items: count.total,
          items_per_page: limit,
        },
      });
    });
  });
});

// POST - Membuat menfess baru (dengan rate limiting)
app.post("/api/menfess", menfessLimiter, (req, res) => {
  const { sender_name, receiver_name, message, song_id } = req.body;
  const ip_address = req.ip || req.connection.remoteAddress;

  // Validasi input
  if (!sender_name || !receiver_name || !message) {
    return res.status(400).json({
      error: "Nama pengirim, nama penerima, dan pesan harus diisi",
    });
  }

  if (sender_name.length > 50 || receiver_name.length > 50) {
    return res.status(400).json({
      error: "Nama pengirim dan penerima maksimal 50 karakter",
    });
  }

  if (message.length > 500) {
    return res.status(400).json({
      error: "Pesan maksimal 500 karakter",
    });
  }

  // Cek apakah song_id valid jika ada
  if (song_id) {
    db.get("SELECT id FROM songs WHERE id = ?", [song_id], (err, song) => {
      if (err || !song) {
        return res.status(400).json({ error: "Lagu tidak ditemukan" });
      }
      insertMenfess();
    });
  } else {
    insertMenfess();
  }

  function insertMenfess() {
    const insertQuery = `
            INSERT INTO menfess (sender_name, receiver_name, message, song_id, ip_address)
            VALUES (?, ?, ?, ?, ?)
        `;

    db.run(
      insertQuery,
      [sender_name, receiver_name, message, song_id || null, ip_address],
      function (err) {
        if (err) {
          return res.status(500).json({ error: "Gagal menyimpan menfess" });
        }

        res.status(201).json({
          message: "Menfess berhasil dikirim",
          id: this.lastID,
        });
      }
    );
  }
});

// GET - Mendapatkan daftar lagu untuk pilihan user
app.get("/api/songs", (req, res) => {
  const query = `
    SELECT 
      id, 
      title, 
      artist, 
      filename,
      thumbnail_filename, 
      thumbnail_url,
      file_size,
      created_at
    FROM songs 
    ORDER BY title ASC
  `;

  db.all(query, [], (err, rows) => {
    if (err) {
      console.error("Songs query error:", err);
      return res.status(500).json({ error: "Database error" });
    }

    console.log(`Returning ${rows.length} songs`);
    res.json({ data: rows });
  });
});

// GET - Get trending menfess (top 3)
app.get("/api/menfess/trending", (req, res) => {
  const query = `
    SELECT 
      m.*,
      s.id as song_id,
      s.title as song_title, 
      s.artist as song_artist,
      s.filename as song_filename,
      s.thumbnail_filename as song_thumbnail_filename,
      s.thumbnail_url as song_thumbnail_url,
      (
        SELECT COUNT(*) FROM menfess_likes ml 
        WHERE ml.menfess_id = m.id 
        AND ml.created_at >= datetime('now', '-7 days')
      ) as trending_score
    FROM menfess m 
    LEFT JOIN songs s ON m.song_id = s.id 
    WHERE m.likes_count > 0
    ORDER BY trending_score DESC, m.likes_count DESC, m.created_at DESC
    LIMIT 3
  `;

  db.all(query, [], (err, rows) => {
    if (err) {
      console.error("Trending query error:", err);
      return res.status(500).json({ error: "Database error" });
    }

    const trendingData = rows.map((row) => ({
      id: row.id,
      sender_name: row.sender_name,
      receiver_name: row.receiver_name,
      message: row.message,
      likes_count: row.likes_count || 0,
      trending_score: row.trending_score || 0,
      song: row.song_id
        ? {
            id: row.song_id,
            title: row.song_title,
            artist: row.song_artist,
            filename: row.song_filename,
            thumbnail_filename: row.song_thumbnail_filename,
            thumbnail_url: row.song_thumbnail_url,
          }
        : null,
      created_at: row.created_at,
    }));

    res.json({ data: trendingData });
  });
});

// ========== ADMIN ROUTES ==========

// POST - Admin login
app.post("/api/admin/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username dan password harus diisi" });
  }

  db.get(
    "SELECT * FROM admins WHERE username = ?",
    [username],
    (err, admin) => {
      if (err) {
        return res.status(500).json({ error: "Database error" });
      }

      if (!admin || !bcrypt.compareSync(password, admin.password)) {
        return res.status(401).json({ error: "Username atau password salah" });
      }

      const token = jwt.sign(
        { id: admin.id, username: admin.username },
        process.env.JWT_SECRET,
        { expiresIn: "24h" }
      );

      res.json({
        message: "Login berhasil",
        token: token,
        admin: {
          id: admin.id,
          username: admin.username,
        },
      });
    }
  );
});

// GET - Admin dashboard stats
app.get("/api/admin/stats", authenticateAdmin, (req, res) => {
  Promise.all([
    new Promise((resolve, reject) => {
      db.get("SELECT COUNT(*) as count FROM menfess", (err, result) => {
        if (err) reject(err);
        else resolve(result.count);
      });
    }),
    new Promise((resolve, reject) => {
      db.get("SELECT COUNT(*) as count FROM songs", (err, result) => {
        if (err) reject(err);
        else resolve(result.count);
      });
    }),
    new Promise((resolve, reject) => {
      db.get(
        'SELECT COUNT(*) as count FROM menfess WHERE date(created_at) = date("now")',
        (err, result) => {
          if (err) reject(err);
          else resolve(result.count);
        }
      );
    }),
    new Promise((resolve, reject) => {
      db.get("SELECT SUM(likes_count) as total FROM menfess", (err, result) => {
        if (err) reject(err);
        else resolve(result.total || 0);
      });
    }),
  ])
    .then(([totalMenfess, totalSongs, todayMenfess, totalLikes]) => {
      res.json({
        total_menfess: totalMenfess,
        total_songs: totalSongs,
        today_menfess: todayMenfess,
        total_likes: totalLikes,
      });
    })
    .catch((err) => {
      console.error("Stats error:", err);
      res.status(500).json({ error: "Database error" });
    });
});

// CRUD Menfess untuk Admin

// GET - Admin get all menfess with details
app.get("/api/admin/menfess", authenticateAdmin, (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 50;
  const offset = (page - 1) * limit;

  const query = `
        SELECT m.*, s.title as song_title, s.artist as song_artist 
        FROM menfess m 
        LEFT JOIN songs s ON m.song_id = s.id 
        ORDER BY m.created_at DESC 
        LIMIT ? OFFSET ?
    `;

  db.all(query, [limit, offset], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: "Database error" });
    }

    db.get("SELECT COUNT(*) as total FROM menfess", (err, count) => {
      if (err) {
        return res.status(500).json({ error: "Database error" });
      }

      res.json({
        data: rows,
        pagination: {
          current_page: page,
          total_pages: Math.ceil(count.total / limit),
          total_items: count.total,
          items_per_page: limit,
        },
      });
    });
  });
});

// DELETE - Admin delete menfess
app.delete("/api/admin/menfess/:id", authenticateAdmin, (req, res) => {
  const menfessId = req.params.id;

  db.run("DELETE FROM menfess WHERE id = ?", [menfessId], function (err) {
    if (err) {
      return res.status(500).json({ error: "Database error" });
    }

    if (this.changes === 0) {
      return res.status(404).json({ error: "Menfess tidak ditemukan" });
    }

    res.json({ message: "Menfess berhasil dihapus" });
  });
});

// CRUD Songs untuk Admin

// GET - Admin get all songs
app.get("/api/admin/songs", authenticateAdmin, (req, res) => {
  const query = `
    SELECT 
      id, 
      title, 
      artist, 
      filename,
      thumbnail_filename, 
      thumbnail_url,
      file_size,
      created_at
    FROM songs 
    ORDER BY created_at DESC
  `;

  db.all(query, [], (err, rows) => {
    if (err) {
      console.error("Admin songs query error:", err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json({ data: rows });
  });
});

// POST - Admin upload song
app.post(
  "/api/admin/songs",
  authenticateAdmin,
  (req, res, next) => {
    console.log("=== UPLOAD REQUEST RECEIVED ===");
    console.log("Content-Type:", req.headers["content-type"]);
    next();
  },
  upload.fields([
    { name: "song", maxCount: 1 },
    { name: "audio", maxCount: 1 },
    { name: "file", maxCount: 1 },
    { name: "thumbnail", maxCount: 1 },
  ]),
  (req, res) => {
    console.log("=== PROCESSING UPLOAD ===");
    console.log("Files received:", req.files);
    console.log("Body received:", req.body);

    const { title, artist, thumbnail_url } = req.body;

    // Check for audio file in any of the possible field names
    const songFile =
      req.files?.song?.[0] || req.files?.audio?.[0] || req.files?.file?.[0];

    if (!title) {
      console.log("Missing title");
      return res.status(400).json({ error: "Judul lagu harus diisi" });
    }

    if (!songFile) {
      console.log("Missing audio file");
      return res.status(400).json({
        error: "File audio harus diisi",
        debug: {
          receivedFiles: Object.keys(req.files || {}),
          expectedFields: ["song", "audio", "file"],
        },
      });
    }

    const thumbnailFile = req.files?.thumbnail?.[0];

    // Validate thumbnail URL if provided
    let finalThumbnailUrl = null;
    if (thumbnail_url && thumbnail_url.trim()) {
      try {
        new URL(thumbnail_url.trim());
        finalThumbnailUrl = thumbnail_url.trim();
      } catch (e) {
        console.log("Invalid thumbnail URL provided:", thumbnail_url);
      }
    }

    console.log("=== SAVING TO DATABASE ===");
    console.log({
      title,
      artist: artist || "Unknown Artist",
      songFileName: songFile.filename,
      songSize: songFile.size,
      thumbnailFileName: thumbnailFile?.filename || null,
      thumbnailUrl: finalThumbnailUrl,
    });

    const insertQuery = `
        INSERT INTO songs (title, artist, filename, thumbnail_filename, thumbnail_url, file_size)
        VALUES (?, ?, ?, ?, ?, ?)
    `;

    db.run(
      insertQuery,
      [
        title,
        artist || "Unknown Artist",
        songFile.filename,
        thumbnailFile ? thumbnailFile.filename : null,
        finalThumbnailUrl,
        songFile.size,
      ],
      function (err) {
        if (err) {
          console.error("=== DATABASE ERROR ===");
          console.error(err);
          return res.status(500).json({
            error: "Gagal menyimpan lagu ke database",
            details: err.message,
          });
        }

        console.log("=== SUCCESS ===");
        console.log("Song saved with ID:", this.lastID);

        res.status(201).json({
          message: "Lagu berhasil diupload",
          id: this.lastID,
          song: {
            id: this.lastID,
            title: title,
            artist: artist || "Unknown Artist",
            filename: songFile.filename,
            thumbnail_filename: thumbnailFile?.filename || null,
            thumbnail_url: finalThumbnailUrl,
            file_size: songFile.size,
          },
        });
      }
    );
  }
);

// Enhanced DELETE - Admin delete song (with file cleanup)
app.delete("/api/admin/songs/:id", authenticateAdmin, (req, res) => {
  const songId = req.params.id;

  // First get song info to delete files
  db.get(
    "SELECT filename, thumbnail_filename FROM songs WHERE id = ?",
    [songId],
    (err, song) => {
      if (err) {
        console.error("Error fetching song for deletion:", err);
        return res.status(500).json({ error: "Database error" });
      }

      if (!song) {
        return res.status(404).json({ error: "Lagu tidak ditemukan" });
      }

      // Delete from database first
      db.run("DELETE FROM songs WHERE id = ?", [songId], function (err) {
        if (err) {
          console.error("Error deleting song from database:", err);
          return res.status(500).json({ error: "Database error" });
        }

        // Then try to delete files (don't fail if files don't exist)
        try {
          const audioPath = path.join(
            __dirname,
            "uploads",
            "songs",
            song.filename
          );
          if (fs.existsSync(audioPath)) {
            fs.unlinkSync(audioPath);
            console.log(`Deleted audio file: ${audioPath}`);
          }

          if (song.thumbnail_filename) {
            const thumbnailPath = path.join(
              __dirname,
              "uploads",
              "thumbnails",
              song.thumbnail_filename
            );
            if (fs.existsSync(thumbnailPath)) {
              fs.unlinkSync(thumbnailPath);
              console.log(`Deleted thumbnail file: ${thumbnailPath}`);
            }
          }
        } catch (fileError) {
          console.error("Error deleting files:", fileError);
          // Continue anyway since database deletion succeeded
        }

        res.json({ message: "Lagu berhasil dihapus" });
      });
    }
  );
});

// PUT - Admin update song
app.put(
  "/api/admin/songs/:id",
  authenticateAdmin,
  upload.fields([{ name: "thumbnail", maxCount: 1 }]),
  (req, res) => {
    const songId = req.params.id;
    const { title, artist, thumbnail_url } = req.body;

    console.log("=== UPDATE SONG REQUEST ===");
    console.log("Song ID:", songId);
    console.log("Body:", req.body);
    console.log("Files:", req.files);

    if (!title || !title.trim()) {
      return res.status(400).json({ error: "Judul lagu harus diisi" });
    }

    // Get current song data first
    db.get("SELECT * FROM songs WHERE id = ?", [songId], (err, currentSong) => {
      if (err) {
        console.error("Error fetching current song:", err);
        return res.status(500).json({ error: "Database error" });
      }

      if (!currentSong) {
        return res.status(404).json({ error: "Lagu tidak ditemukan" });
      }

      const thumbnailFile = req.files?.thumbnail?.[0];
      let updateThumbnailFilename = currentSong.thumbnail_filename;
      let updateThumbnailUrl = currentSong.thumbnail_url;

      // Handle thumbnail update
      if (thumbnailFile) {
        // New thumbnail file uploaded
        updateThumbnailFilename = thumbnailFile.filename;
        updateThumbnailUrl = null; // Clear URL if file is uploaded

        // Delete old thumbnail file if exists
        if (currentSong.thumbnail_filename) {
          const oldThumbnailPath = path.join(
            __dirname,
            "uploads",
            "thumbnails",
            currentSong.thumbnail_filename
          );
          if (fs.existsSync(oldThumbnailPath)) {
            try {
              fs.unlinkSync(oldThumbnailPath);
              console.log("Deleted old thumbnail:", oldThumbnailPath);
            } catch (error) {
              console.error("Error deleting old thumbnail:", error);
            }
          }
        }
      } else if (thumbnail_url && thumbnail_url.trim()) {
        // New thumbnail URL provided
        try {
          new URL(thumbnail_url.trim());
          updateThumbnailUrl = thumbnail_url.trim();

          // Delete old thumbnail file if exists since we're using URL now
          if (currentSong.thumbnail_filename) {
            const oldThumbnailPath = path.join(
              __dirname,
              "uploads",
              "thumbnails",
              currentSong.thumbnail_filename
            );
            if (fs.existsSync(oldThumbnailPath)) {
              try {
                fs.unlinkSync(oldThumbnailPath);
                console.log(
                  "Deleted old thumbnail file (switching to URL):",
                  oldThumbnailPath
                );
              } catch (error) {
                console.error("Error deleting old thumbnail:", error);
              }
            }
            updateThumbnailFilename = null;
          }
        } catch (e) {
          console.log("Invalid thumbnail URL provided:", thumbnail_url);
          // Keep existing thumbnail settings if URL is invalid
        }
      }

      // Update database
      const updateQuery = `
        UPDATE songs 
        SET title = ?, artist = ?, thumbnail_filename = ?, thumbnail_url = ?
        WHERE id = ?
      `;

      db.run(
        updateQuery,
        [
          title.trim(),
          artist?.trim() || "Unknown Artist",
          updateThumbnailFilename,
          updateThumbnailUrl,
          songId,
        ],
        function (err) {
          if (err) {
            console.error("Database update error:", err);
            return res.status(500).json({
              error: "Gagal mengupdate lagu",
              details: err.message,
            });
          }

          if (this.changes === 0) {
            return res.status(404).json({ error: "Lagu tidak ditemukan" });
          }

          console.log("Song updated successfully");

          // Return updated song data
          db.get(
            "SELECT * FROM songs WHERE id = ?",
            [songId],
            (err, updatedSong) => {
              if (err) {
                console.error("Error fetching updated song:", err);
                return res.status(500).json({ error: "Database error" });
              }

              res.json({
                message: "Lagu berhasil diupdate",
                song: updatedSong,
              });
            }
          );
        }
      );
    });
  }
);

// POST - Like/Unlike a menfess
app.post("/api/menfess/:id/like", menfessLimiter, (req, res) => {
  const menfessId = parseInt(req.params.id);
  const ip_address = req.ip || req.connection.remoteAddress;
  const user_fingerprint =
    req.body.fingerprint || req.headers["user-agent"] || "anonymous";

  if (!menfessId) {
    return res.status(400).json({ error: "ID menfess tidak valid" });
  }

  // Check if user already liked this menfess
  db.get(
    "SELECT id FROM menfess_likes WHERE menfess_id = ? AND ip_address = ? AND user_fingerprint = ?",
    [menfessId, ip_address, user_fingerprint],
    (err, existingLike) => {
      if (err) {
        console.error("Error checking existing like:", err);
        return res.status(500).json({ error: "Database error" });
      }

      if (existingLike) {
        // Unlike - remove the like
        db.run(
          "DELETE FROM menfess_likes WHERE id = ?",
          [existingLike.id],
          function (err) {
            if (err) {
              console.error("Error removing like:", err);
              return res.status(500).json({ error: "Database error" });
            }

            // Update likes count
            db.run(
              "UPDATE menfess SET likes_count = likes_count - 1 WHERE id = ?",
              [menfessId],
              function (err) {
                if (err) {
                  console.error("Error updating likes count:", err);
                  return res.status(500).json({ error: "Database error" });
                }

                // Get updated count
                db.get(
                  "SELECT likes_count FROM menfess WHERE id = ?",
                  [menfessId],
                  (err, result) => {
                    if (err) {
                      console.error("Error getting updated count:", err);
                      return res.status(500).json({ error: "Database error" });
                    }

                    res.json({
                      message: "Like dihapus",
                      liked: false,
                      likes_count: result ? result.likes_count : 0,
                    });
                  }
                );
              }
            );
          }
        );
      } else {
        // Like - add new like
        db.run(
          "INSERT INTO menfess_likes (menfess_id, ip_address, user_fingerprint) VALUES (?, ?, ?)",
          [menfessId, ip_address, user_fingerprint],
          function (err) {
            if (err) {
              console.error("Error adding like:", err);
              return res.status(500).json({ error: "Database error" });
            }

            // Update likes count
            db.run(
              "UPDATE menfess SET likes_count = likes_count + 1 WHERE id = ?",
              [menfessId],
              function (err) {
                if (err) {
                  console.error("Error updating likes count:", err);
                  return res.status(500).json({ error: "Database error" });
                }

                // Get updated count
                db.get(
                  "SELECT likes_count FROM menfess WHERE id = ?",
                  [menfessId],
                  (err, result) => {
                    if (err) {
                      console.error("Error getting updated count:", err);
                      return res.status(500).json({ error: "Database error" });
                    }

                    res.json({
                      message: "Like ditambahkan",
                      liked: true,
                      likes_count: result ? result.likes_count : 1,
                    });
                  }
                );
              }
            );
          }
        );
      }
    }
  );
});

// GET - Check if user liked a menfess
app.get("/api/menfess/:id/like-status", (req, res) => {
  const menfessId = parseInt(req.params.id);
  const ip_address = req.ip || req.connection.remoteAddress;
  const user_fingerprint =
    req.query.fingerprint || req.headers["user-agent"] || "anonymous";

  db.get(
    "SELECT id FROM menfess_likes WHERE menfess_id = ? AND ip_address = ? AND user_fingerprint = ?",
    [menfessId, ip_address, user_fingerprint],
    (err, result) => {
      if (err) {
        console.error("Error checking like status:", err);
        return res.status(500).json({ error: "Database error" });
      }

      res.json({ liked: !!result });
    }
  );
});

// Enhanced error handling middleware
app.use((error, req, res, next) => {
  console.error("=== ERROR MIDDLEWARE ===");
  console.error("Error type:", error.constructor.name);
  console.error("Error message:", error.message);

  if (error instanceof multer.MulterError) {
    if (error.code === "LIMIT_FILE_SIZE") {
      return res.status(400).json({
        error: "File terlalu besar, maksimal 10MB",
        code: "FILE_TOO_LARGE",
      });
    }
    if (error.code === "LIMIT_UNEXPECTED_FILE") {
      return res.status(400).json({
        error: "Field file tidak dikenal atau terlalu banyak file",
        code: "UNEXPECTED_FIELD",
      });
    }
    return res.status(400).json({
      error: `Upload error: ${error.message}`,
      code: error.code,
    });
  }

  if (
    error.message.includes("tidak valid") ||
    error.message.includes("diizinkan")
  ) {
    return res.status(400).json({
      error: error.message,
      code: "INVALID_FILE_TYPE",
    });
  }

  res.status(500).json({
    error: error.message || "Internal server error",
    code: "INTERNAL_ERROR",
  });
});

// 404 handler
app.use("*", (req, res) => {
  res.status(404).json({ error: "Endpoint tidak ditemukan" });
});

// Graceful shutdown
process.on("SIGINT", () => {
  console.log("\nShutting down gracefully...");
  db.close((err) => {
    if (err) {
      console.error("Error closing database:", err);
    } else {
      console.log("Database connection closed");
    }
    process.exit(0);
  });
});

// Move server startup to separate function
function startServer() {
  // Ensure upload directories exist
  const uploadDirs = [
    path.join(__dirname, "uploads"),
    path.join(__dirname, "uploads", "songs"),
    path.join(__dirname, "uploads", "thumbnails"),
  ];

  uploadDirs.forEach((dir) => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
      console.log(`Created directory: ${dir}`);
    }
  });

  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || "development"}`);
    console.log(`Health check: http://localhost:${PORT}/api/health`);
    console.log(
      `Audio endpoint: http://localhost:${PORT}/api/audio/[filename]`
    );
    console.log(
      `Thumbnail endpoint: http://localhost:${PORT}/api/thumbnails/[filename]`
    );
  });
}
