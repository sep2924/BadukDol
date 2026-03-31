require('dotenv').config();
const express     = require('express');
const mongoose    = require('mongoose');
const bcrypt      = require('bcryptjs');
const jwt         = require('jsonwebtoken');
const cors        = require('cors');
const { v4: uuidv4 } = require('uuid');
const { createServer } = require('http');
const { Server }  = require('socket.io');
const path        = require('path');

const app    = express();
const httpServer = createServer(app);
const io     = new Server(httpServer, {
  cors: { origin: '*', methods: ['GET','POST'] }
});

app.use(cors({ origin: process.env.CLIENT_ORIGIN || '*', credentials: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname)));

mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/grandmaster')
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => { console.error('❌ MongoDB error:', err); process.exit(1); });

/* ── SCHEMAS ── */
const userSchema = new mongoose.Schema({
  username:   { type: String, required: true, unique: true, trim: true },
  password:   { type: String },
  avatar:     { type: String, default: '🎯' },
  isGuest:    { type: Boolean, default: false },
  guestToken: { type: String },
  stats: {
    wins:   { type: Number, default: 0 },
    losses: { type: Number, default: 0 },
    draws:  { type: Number, default: 0 },
  },
  savedGame: { type: mongoose.Schema.Types.Mixed, default: null },
  createdAt: { type: Date, default: Date.now },
});
const gameSchema = new mongoose.Schema({
  userId:   { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  gameType: { type: String, enum: ['baduk','gomoku'] },
  mode:     { type: String, enum: ['ai','friend','online'] },
  aiLevel:  { type: Number },
  result:   { type: String, enum: ['win','loss','draw','unfinished'] },
  playedAt: { type: Date, default: Date.now },
  duration: { type: Number },
});
const User = mongoose.model('User', userSchema);
const Game = mongoose.model('Game', gameSchema);

/* ── AUTH HELPERS ── */
const JWT_SECRET = process.env.JWT_SECRET || 'change_me';
const AVATARS    = ['🎯','🏆','⚔️','🌙','🔥','🐉','🦅','🌸','⚡','🎭'];
function signToken(id) { return jwt.sign({ id }, JWT_SECRET, { expiresIn: '30d' }); }
function publicUser(u) {
  return { id: u._id, username: u.username, avatar: u.avatar, isGuest: u.isGuest, guestToken: u.guestToken, stats: u.stats };
}
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(h.slice(7), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}
function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}

/* ── REST ROUTES ── */
app.post('/api/auth/guest', async (req, res) => {
  try {
    const guestToken = uuidv4();
    const user = await User.create({
      username: `Guest_${Math.floor(Math.random()*9000)+1000}`,
      avatar: AVATARS[Math.floor(Math.random()*AVATARS.length)],
      isGuest: true, guestToken,
    });
    res.json({ token: signToken(user._id), user: publicUser(user) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password, avatar, guestUpgradeToken } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password are required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    const hashed = await bcrypt.hash(password, 12);
    let user;
    if (guestUpgradeToken) {
      user = await User.findOne({ guestToken: guestUpgradeToken });
      if (!user) return res.status(404).json({ error: 'Guest session not found' });
      user.username = username; user.password = hashed;
      user.isGuest = false; user.guestToken = undefined;
      if (avatar) user.avatar = avatar;
      await user.save();
    } else {
      user = await User.create({ username, password: hashed, avatar: avatar || '🎯', isGuest: false });
    }
    res.json({ token: signToken(user._id), user: publicUser(user) });
  } catch(e) {
    if (e.code === 11000) return res.status(409).json({ error: 'Username already taken' });
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password are required' });
    const user = await User.findOne({ username });
    if (!user || !user.password) return res.status(401).json({ error: 'Invalid username or password' });
    if (!await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Invalid username or password' });
    res.json({ token: signToken(user._id), user: publicUser(user) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/auth/me', auth, async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json({ user: publicUser(user) });
});

app.patch('/api/profile', auth, async (req, res) => {
  try {
    const { username, avatar } = req.body;
    const update = {};
    if (username) update.username = username;
    if (avatar)   update.avatar   = avatar;
    const user = await User.findByIdAndUpdate(req.user.id, update, { new: true });
    res.json({ user: publicUser(user) });
  } catch(e) {
    if (e.code === 11000) return res.status(409).json({ error: 'Username already taken' });
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/game/save', auth, async (req, res) => {
  try { await User.findByIdAndUpdate(req.user.id, { savedGame: req.body.gameState }); res.json({ ok: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/game/saved', auth, async (req, res) => {
  const user = await User.findById(req.user.id).select('savedGame');
  res.json({ savedGame: user?.savedGame || null });
});
app.post('/api/game/result', auth, async (req, res) => {
  try {
    const { gameType, mode, aiLevel, result, duration } = req.body;
    await Game.create({ userId: req.user.id, gameType, mode, aiLevel, result, duration });
    const inc = {};
    if (result === 'win')  inc['stats.wins']   = 1;
    if (result === 'loss') inc['stats.losses']  = 1;
    if (result === 'draw') inc['stats.draws']   = 1;
    await User.findByIdAndUpdate(req.user.id, { $inc: inc });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/game/history', auth, async (req, res) => {
  const games = await Game.find({ userId: req.user.id }).sort({ playedAt: -1 }).limit(20);
  res.json({ games });
});
app.get('/api/leaderboard', async (req, res) => {
  const users = await User.find({ isGuest: false }).sort({ 'stats.wins': -1 }).limit(20).select('username avatar stats');
  res.json({ leaderboard: users.map(u => ({
    username: u.username, avatar: u.avatar, wins: u.stats.wins, losses: u.stats.losses,
    winRate: u.stats.wins + u.stats.losses > 0 ? Math.round(u.stats.wins/(u.stats.wins+u.stats.losses)*100) : 0,
  }))});
});
app.get('/', (req, res) => res.redirect('/BadukDol.html'));
app.get('/api/health', (_, res) => res.json({ status: 'ok' }));

/* ══════════════════════════════════════════════
   SOCKET.IO — REAL-TIME MULTIPLAYER
══════════════════════════════════════════════ */

const rooms      = new Map(); // roomCode → room object
const queue      = new Map(); // gameType → [socket, ...]
const socketUser = new Map(); // socketId → { userId, username, avatar }

function makeRoomCode() {
  const code = Math.floor(1000 + Math.random() * 9000).toString();
  return rooms.has(code) ? makeRoomCode() : code;
}

function createRoom(code, gameType) {
  const timeLimit = gameType === 'baduk' ? 900 : 600;
  return {
    code, gameType,
    players: [], spectators: [],
    board: null, turn: 1, gameActive: false,
    captured: { black: 0, white: 0 },
    moveHistory: [], lastMove: null,
    timerBlack: timeLimit, timerWhite: timeLimit,
    timerInterval: null,
    rematchVotes: new Set(),
    chat: [],
    createdAt: Date.now(),
  };
}

function boardSize(gameType) { return gameType === 'gomoku' ? 15 : 19; }

function emitRoomState(room) {
  const state = {
    code: room.code, gameType: room.gameType,
    players: room.players.map(p => ({ username: p.username, avatar: p.avatar, color: p.color })),
    spectators: room.spectators.length,
    board: room.board, turn: room.turn, gameActive: room.gameActive,
    captured: room.captured, lastMove: room.lastMove,
    timerBlack: room.timerBlack, timerWhite: room.timerWhite,
    chat: room.chat.slice(-50),
  };
  io.to(room.code).emit('room:state', state);
}

function startTimer(room) {
  if (room.timerInterval) clearInterval(room.timerInterval);
  room.timerInterval = setInterval(() => {
    if (!room.gameActive) { clearInterval(room.timerInterval); return; }
    if (room.turn === 1) room.timerBlack--;
    else                 room.timerWhite--;
    io.to(room.code).emit('room:timer', { black: room.timerBlack, white: room.timerWhite });
    if (room.timerBlack <= 0 || room.timerWhite <= 0) {
      const winner = room.timerBlack <= 0 ? 'White' : 'Black';
      room.gameActive = false;
      clearInterval(room.timerInterval);
      io.to(room.code).emit('room:gameover', { reason: 'timeout', winner });
    }
  }, 1000);
}

io.on('connection', (socket) => {
  console.log('🔌 Client connected:', socket.id);

  // ── AUTHENTICATE (registered users) ──
  socket.on('auth', (token) => {
    const payload = verifyToken(token);
    if (payload) {
      User.findById(payload.id).then(user => {
        if (user) {
          socketUser.set(socket.id, {
            userId: user._id.toString(),
            username: user.username,
            avatar: user.avatar,
          });
          console.log(`✅ Socket auth OK: ${user.username} (${socket.id})`);
          socket.emit('auth:ok', { username: user.username });
        } else {
          console.warn(`⚠️ Socket auth: user not found for token`);
          socket.emit('game:error', 'User not found — please log in again');
        }
      }).catch(err => {
        console.error('Auth DB error:', err);
        socket.emit('game:error', 'Auth error: ' + err.message);
      });
    } else {
      console.warn(`⚠️ Socket auth: invalid token from ${socket.id}`);
      socket.emit('game:error', 'Invalid token — please log in again');
    }
  });

  // ── AUTHENTICATE (guests) ──
  socket.on('auth:guest', ({ username, avatar }) => {
    const uname = username || `Guest_${Math.floor(Math.random()*9000)+1000}`;
    socketUser.set(socket.id, {
      userId: socket.id,
      username: uname,
      avatar: avatar || '🎯',
    });
    console.log(`✅ Socket guest auth OK: ${uname} (${socket.id})`);
    socket.emit('auth:ok', { username: uname });
  });

  // ── CREATE ROOM ──
  socket.on('room:create', ({ gameType }) => {
    const user = socketUser.get(socket.id);
    console.log(`room:create from ${socket.id}, user:`, user, 'gameType:', gameType);
    if (!user) return socket.emit('game:error', 'Not authenticated — please wait a moment and try again');
    const code = makeRoomCode();
    const room = createRoom(code, gameType);
    room.players.push({ socketId: socket.id, ...user, color: 1 }); // BLACK
    rooms.set(code, room);
    socket.join(code);
    console.log(`✅ Room created: ${code} by ${user.username}`);
    socket.emit('room:created', { code, color: 1, gameType });
    emitRoomState(room);
  });

  // ── JOIN ROOM BY CODE ──
  socket.on('room:join', ({ code }) => {
    const user = socketUser.get(socket.id);
    console.log(`room:join from ${socket.id}, user:`, user, 'code:', code);
    if (!user) return socket.emit('game:error', 'Not authenticated — please wait a moment and try again');
    const room = rooms.get(code);
    if (!room) return socket.emit('game:error', `Room "${code}" not found — check the code and try again`);
    if (room.players.length >= 2) {
      // Join as spectator
      room.spectators.push({ socketId: socket.id, ...user });
      socket.join(code);
      socket.emit('room:joined', { code, color: 0, gameType: room.gameType, spectator: true });
      emitRoomState(room);
      return;
    }
    room.players.push({ socketId: socket.id, ...user, color: -1 }); // WHITE
    socket.join(code);
    socket.emit('room:joined', { code, color: -1, gameType: room.gameType, spectator: false });
    // Both players in — start the game
    const size = boardSize(room.gameType);
    room.board = Array.from({ length: size }, () => Array(size).fill(0));
    room.gameActive = true;
    room.moveHistory = [JSON.parse(JSON.stringify(room.board))];
    emitRoomState(room);
    io.to(code).emit('room:start', {
      black: { username: room.players[0].username, avatar: room.players[0].avatar },
      white: { username: room.players[1].username, avatar: room.players[1].avatar },
    });
    console.log(`🎮 Game started in room ${code}: ${room.players[0].username} vs ${room.players[1].username}`);
    startTimer(room);
  });

  // ── MATCHMAKING QUEUE ──
  socket.on('queue:join', ({ gameType }) => {
    const user = socketUser.get(socket.id);
    if (!user) return socket.emit('game:error', 'Not authenticated');
    if (!queue.has(gameType)) queue.set(gameType, []);
    const q = queue.get(gameType);
    if (q.find(s => s.id === socket.id)) return;
    q.push(socket);
    socket.emit('queue:waiting', { position: q.length });
    if (q.length >= 2) {
      const [s1, s2] = q.splice(0, 2);
      const u1 = socketUser.get(s1.id);
      const u2 = socketUser.get(s2.id);
      const code = makeRoomCode();
      const room = createRoom(code, gameType);
      room.players.push({ socketId: s1.id, ...u1, color: 1 });
      room.players.push({ socketId: s2.id, ...u2, color: -1 });
      rooms.set(code, room);
      s1.join(code); s2.join(code);
      const size = boardSize(gameType);
      room.board = Array.from({ length: size }, () => Array(size).fill(0));
      room.gameActive = true;
      room.moveHistory = [JSON.parse(JSON.stringify(room.board))];
      s1.emit('room:joined', { code, color: 1,  gameType, spectator: false });
      s2.emit('room:joined', { code, color: -1, gameType, spectator: false });
      emitRoomState(room);
      io.to(code).emit('room:start', {
        black: { username: u1.username, avatar: u1.avatar },
        white: { username: u2.username, avatar: u2.avatar },
      });
      startTimer(room);
    }
  });

  socket.on('queue:leave', ({ gameType }) => {
    if (queue.has(gameType)) {
      const q = queue.get(gameType).filter(s => s.id !== socket.id);
      queue.set(gameType, q);
    }
  });

  // ── MAKE A MOVE ──
  socket.on('room:move', ({ code, r, c }) => {
    const room = rooms.get(code);
    if (!room || !room.gameActive) return;
    const player = room.players.find(p => p.socketId === socket.id);
    if (!player || player.color !== room.turn) return;
    const size = boardSize(room.gameType);
    if (r < 0 || r >= size || c < 0 || c >= size) return;
    if (room.board[r][c] !== 0) return;
    room.board[r][c] = room.turn;
    room.lastMove = { r, c };
    room.moveHistory.push(JSON.parse(JSON.stringify(room.board)));
    if (room.gameType === 'gomoku' && checkOmokWin(room.board, r, c, room.turn, size)) {
      room.gameActive = false;
      clearInterval(room.timerInterval);
      const winner = room.turn === 1 ? 'Black' : 'White';
      emitRoomState(room);
      io.to(code).emit('room:gameover', { reason: 'five', winner });
      return;
    }
    room.turn = -room.turn;
    emitRoomState(room);
  });

  // ── PASS TURN ──
  socket.on('room:pass', ({ code }) => {
    const room = rooms.get(code);
    if (!room || !room.gameActive) return;
    const player = room.players.find(p => p.socketId === socket.id);
    if (!player || player.color !== room.turn) return;
    room.turn = -room.turn;
    io.to(code).emit('room:passed', { by: player.username });
    emitRoomState(room);
  });

  // ── RESIGN ──
  socket.on('room:resign', ({ code }) => {
    const room = rooms.get(code);
    if (!room || !room.gameActive) return;
    const player = room.players.find(p => p.socketId === socket.id);
    if (!player) return;
    room.gameActive = false;
    clearInterval(room.timerInterval);
    const winner = player.color === 1 ? 'White' : 'Black';
    io.to(code).emit('room:gameover', { reason: 'resign', winner, resignedBy: player.username });
    emitRoomState(room);
  });

  // ── CHAT ──
  socket.on('room:chat', ({ code, message }) => {
    const room = rooms.get(code);
    if (!room) return;
    const user = socketUser.get(socket.id);
    if (!user || !message?.trim()) return;
    const msg = { username: user.username, avatar: user.avatar, text: message.trim().slice(0,200), time: Date.now() };
    room.chat.push(msg);
    io.to(code).emit('room:chatMsg', msg);
  });

  // ── REMATCH ──
  socket.on('room:rematch', ({ code }) => {
    const room = rooms.get(code);
    if (!room) return;
    room.rematchVotes.add(socket.id);
    io.to(code).emit('room:rematchVote', { votes: room.rematchVotes.size, needed: room.players.length });
    if (room.rematchVotes.size >= room.players.length) {
      const size = boardSize(room.gameType);
      const timeLimit = room.gameType === 'baduk' ? 900 : 600;
      room.board = Array.from({ length: size }, () => Array(size).fill(0));
      room.turn = 1;
      room.gameActive = true;
      room.captured = { black: 0, white: 0 };
      room.moveHistory = [JSON.parse(JSON.stringify(room.board))];
      room.lastMove = null;
      room.timerBlack = timeLimit;
      room.timerWhite = timeLimit;
      room.rematchVotes.clear();
      room.players.forEach(p => { p.color = -p.color; });
      emitRoomState(room);
      io.to(code).emit('room:start', {
        black: room.players.find(p => p.color === 1),
        white: room.players.find(p => p.color === -1),
      });
      startTimer(room);
    }
  });

  // ── DISCONNECT ──
  socket.on('disconnect', () => {
    console.log('🔌 Client disconnected:', socket.id);
    socketUser.delete(socket.id);
    queue.forEach((q, gameType) => {
      queue.set(gameType, q.filter(s => s.id !== socket.id));
    });
    rooms.forEach((room, code) => {
      const playerIdx = room.players.findIndex(p => p.socketId === socket.id);
      if (playerIdx !== -1) {
        const player = room.players[playerIdx];
        if (room.gameActive) {
          room.gameActive = false;
          clearInterval(room.timerInterval);
          const winner = player.color === 1 ? 'White' : 'Black';
          io.to(code).emit('room:gameover', { reason: 'disconnect', winner, disconnected: player.username });
        }
        room.players.splice(playerIdx, 1);
        if (room.players.length === 0 && room.spectators.length === 0) {
          rooms.delete(code);
        }
      }
      room.spectators = room.spectators.filter(s => s.socketId !== socket.id);
    });
  });
});

/* ── OMOK WIN CHECK (server-side) ── */
function checkOmokWin(board, r, c, color, size) {
  const dirs = [[0,1],[1,0],[1,1],[1,-1]];
  for (const [dr,dc] of dirs) {
    let cnt = 1;
    for (let d=1;d<5;d++) { const nr=r+dr*d,nc=c+dc*d; if(nr<0||nr>=size||nc<0||nc>=size||board[nr][nc]!==color)break; cnt++; }
    for (let d=1;d<5;d++) { const nr=r-dr*d,nc=c-dc*d; if(nr<0||nr>=size||nc<0||nc>=size||board[nr][nc]!==color)break; cnt++; }
    if (cnt >= 5) return true;
  }
  return false;
}

/* ── START ── */
const PORT = process.env.PORT || 3002;
httpServer.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
