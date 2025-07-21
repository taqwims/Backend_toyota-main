const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const multer = require('multer');
const path = require('path');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

// Konfigurasi database Neon PostgreSQL
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
});

// Konfigurasi multer untuk unggahan file
const storage = multer.diskStorage({
  destination: './uploads/',
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Hanya file gambar yang diizinkan!'), false);
    }
  },
  limits: { fileSize: 1024 * 1024 * 5 }, // Batas 5MB
});

// Middleware
app.use('/api/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['Content-Disposition']
}));
app.use(express.json());

// Middleware untuk verifikasi JWT
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  console.log('Authorization Header:', authHeader); // Debug
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token diperlukan' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log('Decoded Token:', decoded); // Debug
    req.user = decoded;
    next();
  } catch (err) {
    console.error('Token Verification Error:', err.message); // Debug
    return res.status(403).json({ error: 'Token tidak valid' });
  }
};

// Endpoint: Login Admin
app.post('/api/admin/login', async (req, res) => {
  console.log('Request body:', req.body);
  if (!req.body) {
    return res.status(400).json({ error: 'Body permintaan kosong' });
  }
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username dan password diperlukan' });
  }
  try {
    const result = await pool.query('SELECT * FROM admins WHERE username = $1', [username]);
    const admin = result.rows[0];
    console.log('Admin found:', admin);
    if (!admin) {
      return res.status(401).json({ error: 'Username tidak ditemukan' });
    }
    const validPassword = await bcrypt.compare(password, admin.password_hash);
    console.log('Password comparison result:', validPassword);
    if (!validPassword) {
      return res.status(401).json({ error: 'Password salah' });
    }
    const token = jwt.sign({ id: admin.id, username: admin.username, website_id: admin.website_id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.json({ token });
  } catch (err) {
    console.error('Error login:', err.stack);
    res.status(500).json({ error: 'Error server: ' + err.message });
  }
});

// Endpoint: Get Websites (Publik)
app.get('/api/websites', async (req, res) => {
  const { domain } = req.query;
  try {
    let query = 'SELECT * FROM websites';
    const params = [];
    if (domain) {
      query += ' WHERE domain = $1';
      params.push(domain);
    }
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching websites:', err);
    res.status(500).json([]);
  }
});

// Endpoint: Get Sales Info (Publik)
app.get('/api/sales_info', async (req, res) => {
  const { website_id } = req.query;
  try {
    let query = 'SELECT * FROM sales_info';
    const params = [];
    if (website_id) {
      query += ' WHERE website_id = $1';
      params.push(website_id);
    }
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching sales_info:', err);
    res.status(500).json([]);
  }
});

// Endpoint: Get Cars (Publik)
app.get('/api/cars', async (req, res) => {
  const { website_id, slug } = req.query;
  try {
    let query = 'SELECT * FROM cars';
    const params = [];
    if (website_id || slug) {
      query += ' WHERE';
      if (website_id) {
        query += ' website_id = $1';
        params.push(website_id);
      }
      if (slug) {
        query += params.length ? ' AND slug = $2' : ' slug = $1';
        params.push(slug);
      }
    }
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching cars:', err);
    res.status(500).json([]);
  }
});

// Endpoint: Get Testimonials (Publik)
app.get('/api/testimonials', async (req, res) => {
  const { website_id } = req.query;
  try {
    let query = 'SELECT * FROM testimonials';
    const params = [];
    if (website_id) {
      query += ' WHERE website_id = $1';
      params.push(website_id);
    }
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching testimonials:', err);
    res.status(500).json([]);
  }
});

// Endpoint: Get FAQs (Publik)
app.get('/api/faqs', async (req, res) => {
  const { website_id } = req.query;
  try {
    let query = 'SELECT * FROM faqs';
    const params = [];
    if (website_id) {
      query += ' WHERE website_id = $1';
      params.push(website_id);
    }
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching faqs:', err);
    res.status(500).json([]);
  }
});

// Endpoint: Get Admins (Admin Only)
app.get('/api/admins', verifyToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, username, website_id FROM admins');
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching admins:', err);
    res.status(500).json([]);
  }
});

// Endpoint: Create Website (Admin Only)
app.post('/api/websites', verifyToken, async (req, res) => {
  const { domain, name } = req.body;
  if (!domain || !name) {
    return res.status(400).json({ error: 'Domain dan nama diperlukan' });
  }
  try {
    const result = await pool.query(
      'INSERT INTO websites (domain, name) VALUES ($1, $2) RETURNING *',
      [domain, name]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Error creating website:', err);
    res.status(500).json({ error: 'Error server: ' + err.message });
  }
});

// Endpoint: Update Website (Admin Only)
app.put('/api/websites/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  const { domain, name } = req.body;
  if (!domain || !name) {
    return res.status(400).json({ error: 'Domain dan nama diperlukan' });
  }
  try {
    const result = await pool.query(
      'UPDATE websites SET domain = $1, name = $2 WHERE id = $3 RETURNING *',
      [domain, name, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Website tidak ditemukan' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error updating website:', err);
    res.status(500).json({ error: 'Error server: ' + err.message });
  }
});

// Endpoint: Delete Website (Admin Only)
app.delete('/api/websites/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM websites WHERE id = $1 RETURNING *', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Website tidak ditemukan' });
    }
    res.json({ message: 'Website berhasil dihapus' });
  } catch (err) {
    console.error('Error deleting website:', err);
    res.status(500).json({ error: 'Error server: ' + err.message });
  }
});

// Endpoint: Create Sales Info (Admin Only) - Dengan Unggahan File
app.post('/api/sales_info', verifyToken, upload.single('image_url'), async (req, res) => {
  const { website_id, name, phone, location, instagram_url, tiktok_url } = req.body;
  if (!website_id || !name || !phone) {
    return res.status(400).json({ error: 'Website ID, nama, dan telepon diperlukan' });
  }
  try {
    const image_url = req.file ? `/uploads/${req.file.filename}` : null;
    const result = await pool.query(
      'INSERT INTO sales_info (website_id, name, phone, location, image_url, instagram_url, tiktok_url) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [website_id, name, phone, location || null, image_url, instagram_url || null, tiktok_url || null]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Error creating sales_info:', err);
    res.status(500).json({ error: 'Error server: ' + err.message });
  }
});

// Endpoint: Update Sales Info (Admin Only) - Dengan Unggahan File
app.put('/api/sales_info/:id', verifyToken, upload.single('image_url'), async (req, res) => {
  const { id } = req.params;
  const { website_id, name, phone, location, instagram_url, tiktok_url } = req.body;
  if (!website_id || !name || !phone) {
    return res.status(400).json({ error: 'Website ID, nama, dan telepon diperlukan' });
  }
  try {
    // Ambil data lama untuk mempertahankan image_url jika tidak ada unggahan baru
    const existingData = await pool.query('SELECT image_url FROM sales_info WHERE id = $1', [id]);
    const currentImageUrl = existingData.rows[0]?.image_url || null;
    const image_url = req.file ? `/uploads/${req.file.filename}` : currentImageUrl;

    const result = await pool.query(
      'UPDATE sales_info SET website_id = $1, name = $2, phone = $3, location = $4, image_url = $5, instagram_url = $6, tiktok_url = $7 WHERE id = $8 RETURNING *',
      [website_id, name, phone, location || null, image_url, instagram_url || null, tiktok_url || null, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Sales Info tidak ditemukan' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error updating sales_info:', err);
    res.status(500).json({ error: 'Error server: ' + err.message });
  }
});

// Endpoint: Delete Sales Info (Admin Only)
app.delete('/api/sales_info/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM sales_info WHERE id = $1 RETURNING *', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Sales Info tidak ditemukan' });
    }
    res.json({ message: 'Sales Info berhasil dihapus' });
  } catch (err) {
    console.error('Error deleting sales_info:', err);
    res.status(500).json({ error: 'Error server: ' + err.message });
  }
});

// Endpoint: Create Car (Admin Only) - Dengan Unggahan File
app.post('/api/cars', verifyToken, upload.single('image_url'), async (req, res) => {
  const { website_id, slug, name, variant, price, promo, type, description, features, specs } = req.body;
  if (!website_id || !slug || !name || !variant || !price || !type) {
    return res.status(400).json({ error: 'Website ID, slug, nama, varian, harga, dan tipe diperlukan' });
  }
  try {
    const image_url = req.file ? `/uploads/${req.file.filename}` : null;
    const result = await pool.query(
      'INSERT INTO cars (website_id, slug, name, variant, image_url, price, promo, type, description, features, specs) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *',
      [website_id, slug, name, variant, image_url, price, promo || null, type, description || null, features || [], specs || {}]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Error creating car:', err);
    res.status(500).json({ error: 'Error server: ' + err.message });
  }
});

// Endpoint: Update Car (Admin Only) - Dengan Unggahan File
app.put('/api/cars/:id', verifyToken, upload.single('image_url'), async (req, res) => {
  const { id } = req.params;
  const { website_id, slug, name, variant, price, promo, type, description, features, specs } = req.body;
  if (!website_id || !slug || !name || !variant || !price || !type) {
    return res.status(400).json({ error: 'Website ID, slug, nama, varian, harga, dan tipe diperlukan' });
  }
  try {
    // Ambil data lama untuk mempertahankan image_url jika tidak ada unggahan baru
    const existingData = await pool.query('SELECT image_url FROM cars WHERE id = $1', [id]);
    const currentImageUrl = existingData.rows[0]?.image_url || null;
    const image_url = req.file ? `/uploads/${req.file.filename}` : currentImageUrl;

    const result = await pool.query(
      'UPDATE cars SET website_id = $1, slug = $2, name = $3, variant = $4, image_url = $5, price = $6, promo = $7, type = $8, description = $9, features = $10, specs = $11 WHERE id = $12 RETURNING *',
      [website_id, slug, name, variant, image_url, price, promo || null, type, description || null, features || [], specs || {}, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Mobil tidak ditemukan' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error updating car:', err);
    res.status(500).json({ error: 'Error server: ' + err.message });
  }
});

// Endpoint: Delete Car (Admin Only)
app.delete('/api/cars/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM cars WHERE id = $1 RETURNING *', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Mobil tidak ditemukan' });
    }
    res.json({ message: 'Mobil berhasil dihapus' });
  } catch (err) {
    console.error('Error deleting car:', err);
    res.status(500).json({ error: 'Error server: ' + err.message });
  }
});

// Endpoint: Create Testimonial (Admin Only) - Dengan Unggahan File
app.post('/api/testimonials', verifyToken, upload.single('image_url'), async (req, res) => {
  const { website_id, name, car, stars, text } = req.body;
  if (!website_id || !name || !car || !stars || !text) {
    return res.status(400).json({ error: 'Website ID, nama, mobil, bintang, dan teks diperlukan' });
  }
  try {
    const image_url = req.file ? `/uploads/${req.file.filename}` : null;
    const result = await pool.query(
      'INSERT INTO testimonials (website_id, name, image_url, car, stars, text) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [website_id, name, image_url, car, stars, text]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Error creating testimonial:', err);
    res.status(500).json({ error: 'Error server: ' + err.message });
  }
});

// Endpoint: Update Testimonial (Admin Only) - Dengan Unggahan File
app.put('/api/testimonials/:id', verifyToken, upload.single('image_url'), async (req, res) => {
  const { id } = req.params;
  const { website_id, name, car, stars, text } = req.body;
  if (!website_id || !name || !car || !stars || !text) {
    return res.status(400).json({ error: 'Website ID, nama, mobil, bintang, dan teks diperlukan' });
  }
  try {
    // Ambil data lama untuk mempertahankan image_url jika tidak ada unggahan baru
    const existingData = await pool.query('SELECT image_url FROM testimonials WHERE id = $1', [id]);
    const currentImageUrl = existingData.rows[0]?.image_url || null;
    const image_url = req.file ? `/uploads/${req.file.filename}` : currentImageUrl;

    const result = await pool.query(
      'UPDATE testimonials SET website_id = $1, name = $2, image_url = $3, car = $4, stars = $5, text = $6 WHERE id = $7 RETURNING *',
      [website_id, name, image_url, car, stars, text, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Testimoni tidak ditemukan' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error updating testimonial:', err);
    res.status(500).json({ error: 'Error server: ' + err.message });
  }
});

// Endpoint: Delete Testimonial (Admin Only)
app.delete('/api/testimonials/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM testimonials WHERE id = $1 RETURNING *', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Testimoni tidak ditemukan' });
    }
    res.json({ message: 'Testimoni berhasil dihapus' });
  } catch (err) {
    console.error('Error deleting testimonial:', err);
    res.status(500).json({ error: 'Error server: ' + err.message });
  }
});

// Endpoint: Create FAQ (Admin Only)
app.post('/api/faqs', verifyToken, async (req, res) => {
  const { website_id, question, answer } = req.body;
  if (!website_id || !question || !answer) {
    return res.status(400).json({ error: 'Website ID, pertanyaan, dan jawaban diperlukan' });
  }
  try {
    const result = await pool.query(
      'INSERT INTO faqs (website_id, question, answer) VALUES ($1, $2, $3) RETURNING *',
      [website_id, question, answer]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Error creating faq:', err);
    res.status(500).json({ error: 'Error server: ' + err.message });
  }
});

// Endpoint: Update FAQ (Admin Only)
app.put('/api/faqs/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  const { website_id, question, answer } = req.body;
  if (!website_id || !question || !answer) {
    return res.status(400).json({ error: 'Website ID, pertanyaan, dan jawaban diperlukan' });
  }
  try {
    const result = await pool.query(
      'UPDATE faqs SET website_id = $1, question = $2, answer = $3 WHERE id = $4 RETURNING *',
      [website_id, question, answer, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'FAQ tidak ditemukan' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error updating faq:', err);
    res.status(500).json({ error: 'Error server: ' + err.message });
  }
});

// Endpoint: Delete FAQ (Admin Only)
app.delete('/api/faqs/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM faqs WHERE id = $1 RETURNING *', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'FAQ tidak ditemukan' });
    }
    res.json({ message: 'FAQ berhasil dihapus' });
  } catch (err) {
    console.error('Error deleting faq:', err);
    res.status(500).json({ error: 'Error server: ' + err.message });
  }
});

// Endpoint: Create Admin (Admin Only)
app.post('/api/admins', verifyToken, async (req, res) => {
  const { username, password, website_id } = req.body;
  if (!username || !password || !website_id) {
    return res.status(400).json({ error: 'Username, password, dan website ID diperlukan' });
  }
  try {
    const password_hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO admins (username, password_hash, website_id) VALUES ($1, $2, $3) RETURNING id, username, website_id',
      [username, password_hash, website_id]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Error creating admin:', err);
    res.status(500).json({ error: 'Error server: ' + err.message });
  }
});

// Endpoint: Update Admin (Admin Only)
app.put('/api/admins/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  const { username, password, website_id } = req.body;
  if (!username || !website_id) {
    return res.status(400).json({ error: 'Username dan website ID diperlukan' });
  }
  try {
    const updates = [username, website_id];
    let query = 'UPDATE admins SET username = $1, website_id = $2';
    if (password) {
      const password_hash = await bcrypt.hash(password, 10);
      query += ', password_hash = $3';
      updates.push(password_hash);
    }
    query += ' WHERE id = $' + (updates.length + 1) + ' RETURNING id, username, website_id';
    updates.push(id);
    const result = await pool.query(query, updates);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Admin tidak ditemukan' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error updating admin:', err);
    res.status(500).json({ error: 'Error server: ' + err.message });
  }
});

// Endpoint: Delete Admin (Admin Only)
app.delete('/api/admins/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM admins WHERE id = $1 RETURNING *', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Admin tidak ditemukan' });
    }
    res.json({ message: 'Admin berhasil dihapus' });
  } catch (err) {
    console.error('Error deleting admin:', err);
    res.status(500).json({ error: 'Error server: ' + err.message });
  }
});

// Mulai server
pool.connect()
  .then(() => console.log('Connected to Neon PostgreSQL'))
  .catch(err => console.error('Connection error:', err.stack));

app.listen(port, () => {
  console.log(`Server berjalan di port ${port}`);
});