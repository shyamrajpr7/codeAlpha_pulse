const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const Datastore = require('@seald-io/nedb');
const path = require('path');
const multer = require('multer');
const fs = require('fs');

const app = express();
const JWT_SECRET = 'socialmedia_secret_key_2026';

if (!fs.existsSync(path.join(__dirname, 'data'))) fs.mkdirSync(path.join(__dirname, 'data'));
if (!fs.existsSync(path.join(__dirname, 'uploads'))) fs.mkdirSync(path.join(__dirname, 'uploads'));

const usersDB = new Datastore({ filename: path.join(__dirname, 'data/users.db'), autoload: true });
const postsDB = new Datastore({ filename: path.join(__dirname, 'data/posts.db'), autoload: true });
const commentsDB = new Datastore({ filename: path.join(__dirname, 'data/comments.db'), autoload: true });
const followsDB = new Datastore({ filename: path.join(__dirname, 'data/follows.db'), autoload: true });
const likesDB = new Datastore({ filename: path.join(__dirname, 'data/likes.db'), autoload: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, 'uploads')),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, uuidv4() + ext);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 15 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = file.mimetype.startsWith('image/') || file.mimetype.startsWith('audio/');
    cb(ok ? null : new Error('Only image and audio files are allowed'), ok);
  }
});

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend/public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Auth middleware
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Upload endpoint - accepts image and/or audio
app.post('/api/upload', auth, upload.fields([{ name: 'image', maxCount: 1 }, { name: 'audio', maxCount: 1 }]), (req, res) => {
  try {
    const result = {};
    if (req.files?.image?.[0]) result.imageUrl = '/uploads/' + req.files.image[0].filename;
    if (req.files?.audio?.[0]) result.audioUrl = '/uploads/' + req.files.audio[0].filename;
    res.json(result);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Promisify nedb
const dbFind = (db, query, sort) => new Promise((res, rej) => {
  let cursor = db.find(query);
  if (sort) cursor = cursor.sort(sort);
  cursor.exec((err, docs) => err ? rej(err) : res(docs));
});
const dbFindOne = (db, query) => new Promise((res, rej) =>
  db.findOne(query, (err, doc) => err ? rej(err) : res(doc)));
const dbInsert = (db, doc) => new Promise((res, rej) =>
  db.insert(doc, (err, d) => err ? rej(err) : res(d)));
const dbUpdate = (db, query, update, opts = {}) => new Promise((res, rej) =>
  db.update(query, update, opts, (err, n) => err ? rej(err) : res(n)));
const dbRemove = (db, query, opts = {}) => new Promise((res, rej) =>
  db.remove(query, opts, (err, n) => err ? rej(err) : res(n)));
const dbCount = (db, query) => new Promise((res, rej) =>
  db.count(query, (err, n) => err ? rej(err) : res(n)));

// ─── AUTH ROUTES ───────────────────────────────────────────────────────────

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, bio, avatar } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ error: 'Missing fields' });

    const existing = await dbFindOne(usersDB, { $or: [{ username }, { email }] });
    if (existing) return res.status(409).json({ error: 'Username or email already taken' });

    const hashed = await bcrypt.hash(password, 10);
    const user = await dbInsert(usersDB, {
      _id: uuidv4(), username, email, password: hashed,
      bio: bio || '', avatar: avatar || `https://api.dicebear.com/7.x/personas/svg?seed=${username}`,
      createdAt: new Date().toISOString()
    });

    const token = jwt.sign({ id: user._id, username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, username, email, bio: user.bio, avatar: user.avatar } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await dbFindOne(usersDB, { username });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Wrong password' });

    const token = jwt.sign({ id: user._id, username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, username, email: user.email, bio: user.bio, avatar: user.avatar } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── USER ROUTES ───────────────────────────────────────────────────────────

// Get user profile
app.get('/api/users/:username', auth, async (req, res) => {
  try {
    const user = await dbFindOne(usersDB, { username: req.params.username });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const [posts, followers, following, isFollowing] = await Promise.all([
      dbFind(postsDB, { authorId: user._id }, { createdAt: -1 }),
      dbCount(followsDB, { followingId: user._id }),
      dbCount(followsDB, { followerId: user._id }),
      dbFindOne(followsDB, { followerId: req.user.id, followingId: user._id })
    ]);

    // Enrich posts
    const enriched = await Promise.all(posts.map(async p => {
      const [likes, comments, liked] = await Promise.all([
        dbCount(likesDB, { postId: p._id }),
        dbCount(commentsDB, { postId: p._id }),
        dbFindOne(likesDB, { postId: p._id, userId: req.user.id })
      ]);
      return { ...p, likesCount: likes, commentsCount: comments, liked: !!liked };
    }));

    res.json({
      user: { id: user._id, username: user.username, email: user.email, bio: user.bio, avatar: user.avatar, createdAt: user.createdAt },
      posts: enriched, followers, following, isFollowing: !!isFollowing
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Update profile
app.put('/api/users/me', auth, async (req, res) => {
  try {
    const { bio, avatar } = req.body;
    await dbUpdate(usersDB, { _id: req.user.id }, { $set: { bio, avatar } });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Search users
app.get('/api/users', auth, async (req, res) => {
  try {
    const { q } = req.query;
    const all = await dbFind(usersDB, {});
    const filtered = q
      ? all.filter(u => u.username.toLowerCase().includes(q.toLowerCase()))
      : all;
    res.json(filtered.map(u => ({ id: u._id, username: u.username, avatar: u.avatar, bio: u.bio })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── FOLLOW ROUTES ─────────────────────────────────────────────────────────

// Follow / Unfollow
app.post('/api/follow/:userId', auth, async (req, res) => {
  try {
    const followingId = req.params.userId;
    if (followingId === req.user.id)
      return res.status(400).json({ error: "Can't follow yourself" });

    const existing = await dbFindOne(followsDB, { followerId: req.user.id, followingId });
    if (existing) {
      await dbRemove(followsDB, { followerId: req.user.id, followingId });
      res.json({ followed: false });
    } else {
      await dbInsert(followsDB, { _id: uuidv4(), followerId: req.user.id, followingId, createdAt: new Date().toISOString() });
      res.json({ followed: true });
    }
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── POST ROUTES ───────────────────────────────────────────────────────────

// Get feed (posts from followed users + own)
app.get('/api/posts/feed', auth, async (req, res) => {
  try {
    const follows = await dbFind(followsDB, { followerId: req.user.id });
    const ids = [req.user.id, ...follows.map(f => f.followingId)];
    const posts = await dbFind(postsDB, { authorId: { $in: ids } }, { createdAt: -1 });

    const enriched = await Promise.all(posts.map(async p => {
      const author = await dbFindOne(usersDB, { _id: p.authorId });
      const [likes, comments, liked] = await Promise.all([
        dbCount(likesDB, { postId: p._id }),
        dbCount(commentsDB, { postId: p._id }),
        dbFindOne(likesDB, { postId: p._id, userId: req.user.id })
      ]);
      return {
        ...p,
        author: { username: author?.username, avatar: author?.avatar },
        likesCount: likes, commentsCount: comments, liked: !!liked
      };
    }));

    res.json(enriched);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Get all/explore posts
app.get('/api/posts', auth, async (req, res) => {
  try {
    const posts = await dbFind(postsDB, {}, { createdAt: -1 });
    const enriched = await Promise.all(posts.map(async p => {
      const author = await dbFindOne(usersDB, { _id: p.authorId });
      const [likes, comments, liked] = await Promise.all([
        dbCount(likesDB, { postId: p._id }),
        dbCount(commentsDB, { postId: p._id }),
        dbFindOne(likesDB, { postId: p._id, userId: req.user.id })
      ]);
      return {
        ...p,
        author: { username: author?.username, avatar: author?.avatar },
        likesCount: likes, commentsCount: comments, liked: !!liked
      };
    }));
    res.json(enriched);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Create post
app.post('/api/posts', auth, async (req, res) => {
  try {
    const { content, image, audio } = req.body;
    if (!content?.trim() && !image) return res.status(400).json({ error: 'Content or image required' });

    const post = await dbInsert(postsDB, {
      _id: uuidv4(), content: content || '', image: image || null, audio: audio || null,
      authorId: req.user.id, createdAt: new Date().toISOString()
    });

    const author = await dbFindOne(usersDB, { _id: req.user.id });
    res.json({ ...post, author: { username: author.username, avatar: author.avatar }, likesCount: 0, commentsCount: 0, liked: false });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Delete post
app.delete('/api/posts/:id', auth, async (req, res) => {
  try {
    const post = await dbFindOne(postsDB, { _id: req.params.id });
    if (!post) return res.status(404).json({ error: 'Post not found' });
    if (post.authorId !== req.user.id) return res.status(403).json({ error: 'Not your post' });

    await Promise.all([
      dbRemove(postsDB, { _id: req.params.id }),
      dbRemove(commentsDB, { postId: req.params.id }, { multi: true }),
      dbRemove(likesDB, { postId: req.params.id }, { multi: true })
    ]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── LIKE ROUTES ───────────────────────────────────────────────────────────

app.post('/api/posts/:id/like', auth, async (req, res) => {
  try {
    const postId = req.params.id;
    const existing = await dbFindOne(likesDB, { postId, userId: req.user.id });
    if (existing) {
      await dbRemove(likesDB, { postId, userId: req.user.id });
      const count = await dbCount(likesDB, { postId });
      res.json({ liked: false, count });
    } else {
      await dbInsert(likesDB, { _id: uuidv4(), postId, userId: req.user.id, createdAt: new Date().toISOString() });
      const count = await dbCount(likesDB, { postId });
      res.json({ liked: true, count });
    }
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── COMMENT ROUTES ────────────────────────────────────────────────────────

app.get('/api/posts/:id/comments', auth, async (req, res) => {
  try {
    const comments = await dbFind(commentsDB, { postId: req.params.id }, { createdAt: 1 });
    const enriched = await Promise.all(comments.map(async c => {
      const author = await dbFindOne(usersDB, { _id: c.authorId });
      return { ...c, author: { username: author?.username, avatar: author?.avatar } };
    }));
    res.json(enriched);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/posts/:id/comments', auth, async (req, res) => {
  try {
    const { content } = req.body;
    if (!content?.trim()) return res.status(400).json({ error: 'Content required' });

    const comment = await dbInsert(commentsDB, {
      _id: uuidv4(), postId: req.params.id, content,
      authorId: req.user.id, createdAt: new Date().toISOString()
    });
    const author = await dbFindOne(usersDB, { _id: req.user.id });
    res.json({ ...comment, author: { username: author.username, avatar: author.avatar } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/comments/:id', auth, async (req, res) => {
  try {
    const comment = await dbFindOne(commentsDB, { _id: req.params.id });
    if (!comment) return res.status(404).json({ error: 'Not found' });
    if (comment.authorId !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
    await dbRemove(commentsDB, { _id: req.params.id });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Serve frontend for any other route
app.get('/{*splat}', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/public/index.html'));
});

const PORT = 3000;
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));