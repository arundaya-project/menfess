# Menfess API Documentation

## Overview

Menfess API adalah RESTful API untuk aplikasi pesan rahasia (menfess) dengan fitur upload lagu dan manajemen admin.

## Base URLs

### Production
```
https://ptraazxtt.my.id
```

### Development
```
http://localhost:3000
```

## Authentication

API menggunakan JWT (JSON Web Token) untuk autentikasi admin. Token harus disertakan dalam header:

```
Authorization: Bearer <your-jwt-token>
```

## Rate Limiting

- **Global**: 100 requests per 15 menit per IP
- **Menfess Creation**: 5 requests per 5 menit per IP

## Environment Variables

```env
JWT_SECRET=your-generated-jwt-secret
ADMIN_USERNAME=putraasw
ADMIN_PASSWORD=putrabakwan17
CUSTOM_DOMAIN=ptraazxtt.my.id
PORT=3000
```

## CORS Configuration

API dikonfigurasi untuk menerima request dari:
- `https://ptraazxtt.my.id` (Production)
- `http://ptraazxtt.my.id` (Production HTTP)
- `http://localhost:3000` (Development)
- `http://localhost:3001` (Development)
- `http://localhost:5173` (Vite Dev Server)
- `http://localhost:8080` (Development)

---

## Public Endpoints

### 1. Health Check

#### GET `/`

Mengecek status API.

**Example Request:**
```bash
curl https://ptraazxtt.my.id/
```

**Response:**

```json
{
  "message": "Menfess API is running",
  "status": "OK",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

#### GET `/api/health`

Health check endpoint untuk monitoring.

**Example Request:**
```bash
curl https://ptraazxtt.my.id/api/health
```

**Response:**

```json
{
  "message": "API is healthy",
  "status": "OK",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

### 2. Menfess

#### GET `/api/menfess`

Mendapatkan daftar semua menfess dengan pagination.

**Query Parameters:**

- `page` (optional): Nomor halaman (default: 1)
- `limit` (optional): Jumlah item per halaman (default: 20)

**Example Request:**

```
GET /api/menfess?page=1&limit=10
```

**Response:**

```json
{
  "data": [
    {
      "id": 1,
      "sender_name": "Anonim",
      "receiver_name": "Crush",
      "message": "Hai, aku suka sama kamu...",
      "song": {
        "id": 1,
        "title": "Perfect",
        "artist": "Ed Sheeran"
      },
      "created_at": "2024-01-15T10:30:00.000Z"
    }
  ],
  "pagination": {
    "current_page": 1,
    "total_pages": 5,
    "total_items": 100,
    "items_per_page": 20
  }
}
```

#### POST `/api/menfess`

Membuat menfess baru.

**Rate Limit:** 5 requests per 5 menit per IP

**Request Body:**

```json
{
  "sender_name": "Anonim",
  "receiver_name": "Crush",
  "message": "Pesan rahasia untuk kamu...",
  "song_id": 1
}
```

**Validation:**

- `sender_name`: Required, max 50 karakter
- `receiver_name`: Required, max 50 karakter
- `message`: Required, max 500 karakter
- `song_id`: Optional, harus valid song ID

**Response:**

```json
{
  "message": "Menfess berhasil dikirim",
  "id": 123
}
```

**Error Responses:**

```json
{
  "error": "Nama pengirim, nama penerima, dan pesan harus diisi"
}
```

### 3. Songs

#### GET `/api/songs`

Mendapatkan daftar lagu untuk pilihan user.

**Response:**

```json
{
  "data": [
    {
      "id": 1,
      "title": "Perfect",
      "artist": "Ed Sheeran"
    },
    {
      "id": 2,
      "title": "Thinking Out Loud",
      "artist": "Ed Sheeran"
    }
  ]
}
```

#### GET `/api/songs/:filename`

Mengakses file lagu (protected endpoint).

**Production URL:**
```
https://ptraazxtt.my.id/api/songs/[filename]
```

**Headers Required:**

- `Referer`: Must be from allowed domain (ptraazxtt.my.id or localhost)
- `User-Agent`: Must be from normal browser

**Allowed Domains:**
- `ptraazxtt.my.id`
- `localhost`
- `127.0.0.1`

**Response:** File audio stream

### 4. File Access

#### GET `/api/thumbnails/:filename`

Mengakses file thumbnail lagu.

**Production URL:**
```
https://ptraazxtt.my.id/api/thumbnails/[filename]
```

**Response:** File gambar

#### GET `/api/audio/:filename`

Enhanced audio streaming dengan support untuk range requests.

**Production URL:**
```
https://ptraazxtt.my.id/api/audio/[filename]
```

**Features:**
- Support HTTP Range requests untuk streaming
- CORS headers untuk cross-origin access
- Caching headers untuk performance
- Auto content-type detection

**Response:** Audio stream dengan proper headers

---

## Admin Endpoints

### 1. Authentication

#### POST `/api/admin/login`

Login admin untuk mendapatkan JWT token.

**Request Body:**

```json
{
  "username": "putraasw",
  "password": "putrabakwan17"
}
```

**Response:**

```json
{
  "message": "Login berhasil",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "admin": {
    "id": 1,
    "username": "putraasw"
  }
}
```

**Error Response:**

```json
{
  "error": "Username atau password salah"
}
```

### 2. Dashboard

#### GET `/api/admin/stats`

Mendapatkan statistik dashboard admin.

**Headers:**

```
Authorization: Bearer <jwt-token>
```

**Response:**

```json
{
  "total_menfess": 150,
  "total_songs": 25,
  "today_menfess": 12
}
```

### 3. Menfess Management

#### GET `/api/admin/menfess`

Mendapatkan semua menfess dengan detail lengkap (admin only).

**Headers:**

```
Authorization: Bearer <jwt-token>
```

**Query Parameters:**

- `page` (optional): Nomor halaman (default: 1)
- `limit` (optional): Jumlah item per halaman (default: 50)

**Response:**

```json
{
  "data": [
    {
      "id": 1,
      "sender_name": "Anonim",
      "receiver_name": "Crush",
      "message": "Hai, aku suka sama kamu...",
      "song_id": 1,
      "song_title": "Perfect",
      "song_artist": "Ed Sheeran",
      "ip_address": "192.168.1.1",
      "created_at": "2024-01-15T10:30:00.000Z"
    }
  ],
  "pagination": {
    "current_page": 1,
    "total_pages": 3,
    "total_items": 150,
    "items_per_page": 50
  }
}
```

#### DELETE `/api/admin/menfess/:id`

Menghapus menfess berdasarkan ID.

**Headers:**

```
Authorization: Bearer <jwt-token>
```

**Response:**

```json
{
  "message": "Menfess berhasil dihapus"
}
```

### 4. Songs Management

#### GET `/api/admin/songs`

Mendapatkan semua lagu dengan detail lengkap.

**Headers:**

```
Authorization: Bearer <jwt-token>
```

**Response:**

```json
{
  "data": [
    {
      "id": 1,
      "title": "Perfect",
      "artist": "Ed Sheeran",
      "filename": "1642234567890-123456789.mp3",
      "thumbnail_filename": "1642234567890-987654321.jpg",
      "thumbnail_url": null,
      "file_size": 5242880,
      "created_at": "2024-01-15T10:30:00.000Z"
    }
  ]
}
```

#### POST `/api/admin/songs`

Upload lagu baru dengan thumbnail.

**Headers:**

```
Authorization: Bearer <jwt-token>
Content-Type: multipart/form-data
```

**Form Data:**

- `title`: Judul lagu (required)
- `artist`: Nama artis (optional)
- `song` | `audio` | `file`: File audio (required, max 10MB) - accepts any of these field names
- `thumbnail`: File gambar thumbnail (optional, max 10MB)
- `thumbnail_url`: URL thumbnail eksternal (optional)

**Supported Audio Formats:** mp3, wav, m4a, ogg
**Supported Audio MIME Types:** audio/mpeg, audio/wav, audio/mp4, audio/ogg
**Supported Image Formats:** jpeg, jpg, png, gif, webp

**Response:**

```json
{
  "message": "Lagu berhasil diupload",
  "id": 1,
  "song": {
    "id": 1,
    "title": "Perfect",
    "artist": "Ed Sheeran",
    "filename": "1642234567890-123456789.mp3",
    "thumbnail_filename": "1642234567890-987654321.jpg",
    "file_size": 297257
  }
}
```

**Error Responses:**

```json
{
  "error": "Title dan file lagu harus diisi",
  "received": {
    "title": true,
    "hasAudioFile": false,
    "files": ["thumbnail"],
    "body": {"title": "Song Title", "artist": "Artist Name"}
  }
}
```

#### DELETE `/api/admin/songs/:id`

Menghapus lagu berdasarkan ID.

**Headers:**

```
Authorization: Bearer <jwt-token>
```

**Response:**

```json
{
  "message": "Lagu berhasil dihapus"
}
```

---

## Error Codes

### HTTP Status Codes

- `200` - OK
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `429` - Too Many Requests
- `500` - Internal Server Error

### Common Error Responses

#### Rate Limit Exceeded

```json
{
  "error": "Terlalu banyak request, coba lagi nanti"
}
```

#### Authentication Required

```json
{
  "error": "Access token required"
}
```

#### Invalid Token

```json
{
  "error": "Invalid or expired token"
}
```

#### File Too Large

```json
{
  "error": "File terlalu besar, maksimal 10MB"
}
```

#### Invalid File Type

```json
{
  "error": "Hanya file audio yang diizinkan"
}
```

#### Upload Errors

```json
{
  "error": "Upload error: LIMIT_UNEXPECTED_FILE"
}
```

```json
{
  "error": "Field file tidak dikenal atau terlalu banyak file"
}
```

```json
{
  "error": "Hanya file audio yang diizinkan"
}
```

---

## Setup Instructions

### 1. Installation

```bash
npm install
```

### 2. Environment Setup

Buat file `.env` atau biarkan sistem generate otomatis saat pertama kali run.

### 3. Run Server

```bash
npm start
# atau
node server.js
```

### 4. Database

Database SQLite akan dibuat otomatis di `./menfess.db` saat pertama kali run.

---

## Security Features

1. **Rate Limiting**: Mencegah spam dan abuse
2. **JWT Authentication**: Secure admin access
3. **File Protection**: Anti-scraping untuk file lagu
4. **Input Validation**: Sanitasi dan validasi input
5. **CORS Protection**: Cross-origin resource sharing control
6. **Helmet.js**: Security headers

---

## File Structure

```
uploads/
├── songs/          # File audio lagu
└── thumbnails/     # File thumbnail lagu
menfess.db          # SQLite database
.env                # Environment variables
server.js           # Main server file
```

---

## Logging

Server mencatat semua request dengan format:

```
2024-01-15T10:30:00.000Z - GET /api/menfess
```

---

## Example Usage

### Frontend Integration Example (JavaScript)

### Production Environment

```javascript
const API_BASE_URL = 'https://ptraazxtt.my.id';

// Mengambil daftar menfess
async function getMenfess(page = 1) {
  const response = await fetch(`${API_BASE_URL}/api/menfess?page=${page}`, {
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
    }
  });
  const data = await response.json();
  return data;
}

// Mengirim menfess baru
async function sendMenfess(menfessData) {
  const response = await fetch(`${API_BASE_URL}/api/menfess`, {
    method: "POST",
    credentials: 'include',
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(menfessData),
  });
  return await response.json();
}

// Admin login
async function adminLogin(username, password) {
  const response = await fetch(`${API_BASE_URL}/api/admin/login`, {
    method: "POST",
    credentials: 'include',
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ username, password }),
  });
  const data = await response.json();

  if (data.token) {
    localStorage.setItem("admin_token", data.token);
  }

  return data;
}

// Upload lagu (admin)
async function uploadSong(formData) {
  const token = localStorage.getItem("admin_token");

  const response = await fetch(`${API_BASE_URL}/api/admin/songs`, {
    method: "POST",
    credentials: 'include',
    headers: {
      Authorization: `Bearer ${token}`,
    },
    body: formData, // FormData object
  });

  return await response.json();
}

// Audio player dengan custom domain
function createAudioPlayer(filename) {
  const audio = new Audio();
  audio.src = `${API_BASE_URL}/api/audio/${filename}`;
  audio.crossOrigin = "use-credentials";
  return audio;
}
```

### Development Environment

```javascript
const API_BASE_URL = 'http://localhost:3000';

// Same functions as above but with localhost URL
```

---

## Deployment Notes

### Custom Domain Setup

1. **DNS Configuration:**
   - Point `ptraazxtt.my.id` to your server IP
   - Set up A record or CNAME as needed

2. **SSL Certificate:**
   - Install SSL certificate for HTTPS support
   - Use Let's Encrypt or commercial certificate

3. **Nginx/Apache Configuration:**
   ```nginx
   server {
       listen 80;
       listen 443 ssl;
       server_name ptraazxtt.my.id;

       location / {
           proxy_pass http://localhost:3000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }

       # SSL configuration
       ssl_certificate /path/to/certificate.crt;
       ssl_certificate_key /path/to/private.key;
   }
   ```

4. **Environment Variables:**
   ```env
   NODE_ENV=production
   CUSTOM_DOMAIN=ptraazxtt.my.id
   JWT_SECRET=your-production-jwt-secret
   ADMIN_USERNAME=putraasw
   ADMIN_PASSWORD=putrabakwan17
   PORT=3000
   ```

### Security Considerations

1. **CORS Protection:** Only allows requests from specified domains
2. **File Protection:** Audio files protected from direct access
3. **Rate Limiting:** Prevents abuse and spam
4. **HTTPS Enforcement:** Use HTTPS in production
5. **Domain Validation:** Validates referer and origin headers

---

## Testing

### Test Custom Domain (Local)

Add to `/etc/hosts` (Linux/Mac) or `C:\Windows\System32\drivers\etc\hosts` (Windows):
```
127.0.0.1 ptraazxtt.my.id
```

Then test:
```bash
curl http://ptraazxtt.my.id:3000/api/health
```

### Production Testing

```bash
# Health check
curl https://ptraazxtt.my.id/api/health

# Get menfess
curl https://ptraazxtt.my.id/api/menfess

# Get songs
curl https://ptraazxtt.my.id/api/songs
```
