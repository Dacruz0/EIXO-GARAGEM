const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── BANCO DE DADOS ───────────────────────────────────────────
const db = new Database('eixo.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario TEXT NOT NULL UNIQUE,
    senha TEXT NOT NULL,
    discord TEXT,
    ip TEXT,
    admin INTEGER DEFAULT 0,
    criado_em DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS sessoes (
    token TEXT PRIMARY KEY,
    usuario_id INTEGER NOT NULL,
    criado_em DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
  );

  CREATE TABLE IF NOT EXISTS produtos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    titulo TEXT NOT NULL,
    descricao TEXT,
    preco REAL NOT NULL,
    imagem TEXT,
    criado_em DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS bibliotecas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER NOT NULL,
    nome TEXT NOT NULL,
    UNIQUE(usuario_id, nome),
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
  );

  CREATE TABLE IF NOT EXISTS biblioteca_itens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    biblioteca_id INTEGER NOT NULL,
    produto_id INTEGER NOT NULL,
    adicionado_em DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (biblioteca_id) REFERENCES bibliotecas(id) ON DELETE CASCADE,
    FOREIGN KEY (produto_id) REFERENCES produtos(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS curtidos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER NOT NULL,
    produto_id INTEGER NOT NULL,
    UNIQUE(usuario_id, produto_id),
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id),
    FOREIGN KEY (produto_id) REFERENCES produtos(id) ON DELETE CASCADE
  );
`);

// Criar admin padrão se não existir
const adminExiste = db.prepare('SELECT id FROM usuarios WHERE admin = 1').get();
if (!adminExiste) {
  const hash = bcrypt.hashSync('admin123', 10);
  db.prepare('INSERT OR IGNORE INTO usuarios (usuario, senha, admin, ip) VALUES (?, ?, 1, ?)').run('admin', hash, '0.0.0.0');
  console.log('Admin criado: usuário=admin senha=admin123 — TROQUE A SENHA!');
}

// ─── MIDDLEWARES ──────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// Pasta de uploads
if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');

// ─── UPLOAD ───────────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, 'img_' + Date.now() + ext);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png', '.webp', '.gif'];
    if (allowed.includes(path.extname(file.originalname).toLowerCase())) cb(null, true);
    else cb(new Error('Formato inválido'));
  }
});

// ─── HELPERS ─────────────────────────────────────────────────
function gerarToken() {
  return Math.random().toString(36).substr(2) + Math.random().toString(36).substr(2) + Date.now().toString(36);
}

function getIP(req) {
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
}

function autenticar(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ erro: 'Não autenticado' });
  const sessao = db.prepare('SELECT * FROM sessoes WHERE token = ?').get(token);
  if (!sessao) return res.status(401).json({ erro: 'Sessão inválida' });
  req.usuarioId = sessao.usuario_id;
  req.usuario = db.prepare('SELECT * FROM usuarios WHERE id = ?').get(sessao.usuario_id);
  next();
}

function apenasAdmin(req, res, next) {
  if (!req.usuario || !req.usuario.admin) return res.status(403).json({ erro: 'Acesso negado' });
  next();
}

// ─── ROTAS: AUTH ──────────────────────────────────────────────
app.post('/api/registro', (req, res) => {
  const { usuario, senha, discord } = req.body;
  const ip = getIP(req);

  if (!usuario || !senha) return res.status(400).json({ erro: 'Usuário e senha são obrigatórios' });
  if (usuario.length < 3) return res.status(400).json({ erro: 'Usuário muito curto (mín. 3)' });
  if (senha.length < 6) return res.status(400).json({ erro: 'Senha muito curta (mín. 6)' });

  // Limite de 4 contas por IP
  const contasPorIP = db.prepare('SELECT COUNT(*) as total FROM usuarios WHERE ip = ?').get(ip);
  if (contasPorIP.total >= 4) return res.status(429).json({ erro: 'Limite de 4 contas por IP atingido' });

  const jaExiste = db.prepare('SELECT id FROM usuarios WHERE usuario = ?').get(usuario);
  if (jaExiste) return res.status(400).json({ erro: 'Usuário já existe' });

  const hash = bcrypt.hashSync(senha, 10);
  const result = db.prepare('INSERT INTO usuarios (usuario, senha, discord, ip) VALUES (?, ?, ?, ?)').run(usuario, hash, discord || null, ip);

  // Criar biblioteca padrão
  db.prepare('INSERT INTO bibliotecas (usuario_id, nome) VALUES (?, ?)').run(result.lastInsertRowid, 'PADRÃO');

  const token = gerarToken();
  db.prepare('INSERT INTO sessoes (token, usuario_id) VALUES (?, ?)').run(token, result.lastInsertRowid);

  res.json({ token, usuario, admin: 0 });
});

app.post('/api/login', (req, res) => {
  const { usuario, senha } = req.body;
  if (!usuario || !senha) return res.status(400).json({ erro: 'Preencha todos os campos' });

  const user = db.prepare('SELECT * FROM usuarios WHERE usuario = ?').get(usuario);
  if (!user || !bcrypt.compareSync(senha, user.senha)) return res.status(401).json({ erro: 'Usuário ou senha inválidos' });

  const token = gerarToken();
  db.prepare('INSERT INTO sessoes (token, usuario_id) VALUES (?, ?)').run(token, user.id);

  res.json({ token, usuario: user.usuario, admin: user.admin });
});

app.post('/api/logout', autenticar, (req, res) => {
  db.prepare('DELETE FROM sessoes WHERE usuario_id = ?').run(req.usuarioId);
  res.json({ ok: true });
});

app.get('/api/me', autenticar, (req, res) => {
  const u = req.usuario;
  res.json({ id: u.id, usuario: u.usuario, discord: u.discord, admin: u.admin });
});

// ─── ROTAS: PRODUTOS ──────────────────────────────────────────
app.get('/api/produtos', (req, res) => {
  const produtos = db.prepare('SELECT * FROM produtos ORDER BY criado_em DESC').all();
  res.json(produtos);
});

app.post('/api/produtos', autenticar, apenasAdmin, upload.single('imagem'), (req, res) => {
  const { titulo, descricao, preco } = req.body;
  if (!titulo || !preco) return res.status(400).json({ erro: 'Título e preço são obrigatórios' });
  const imagem = req.file ? '/uploads/' + req.file.filename : null;
  const result = db.prepare('INSERT INTO produtos (titulo, descricao, preco, imagem) VALUES (?, ?, ?, ?)').run(titulo, descricao || '', parseFloat(preco), imagem);
  res.json({ id: result.lastInsertRowid, titulo, descricao, preco: parseFloat(preco), imagem });
});

app.delete('/api/produtos/:id', autenticar, apenasAdmin, (req, res) => {
  const produto = db.prepare('SELECT * FROM produtos WHERE id = ?').get(req.params.id);
  if (!produto) return res.status(404).json({ erro: 'Produto não encontrado' });
  // Deletar imagem do disco
  if (produto.imagem) {
    const filePath = path.join(__dirname, produto.imagem);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  }
  db.prepare('DELETE FROM produtos WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ─── ROTAS: BIBLIOTECAS ───────────────────────────────────────
app.get('/api/bibliotecas', autenticar, (req, res) => {
  const bibs = db.prepare('SELECT * FROM bibliotecas WHERE usuario_id = ?').all(req.usuarioId);
  const result = {};
  bibs.forEach(b => {
    const itens = db.prepare(`
      SELECT bi.id as item_id, p.id, p.titulo, p.preco, p.imagem
      FROM biblioteca_itens bi
      JOIN produtos p ON p.id = bi.produto_id
      WHERE bi.biblioteca_id = ?
    `).all(b.id);
    result[b.nome] = { id: b.id, itens };
  });
  res.json(result);
});

app.post('/api/bibliotecas', autenticar, (req, res) => {
  const { nome } = req.body;
  if (!nome) return res.status(400).json({ erro: 'Nome obrigatório' });
  try {
    const result = db.prepare('INSERT INTO bibliotecas (usuario_id, nome) VALUES (?, ?)').run(req.usuarioId, nome.toUpperCase());
    res.json({ id: result.lastInsertRowid, nome: nome.toUpperCase() });
  } catch {
    res.status(400).json({ erro: 'Coleção já existe' });
  }
});

app.delete('/api/bibliotecas/:id', autenticar, (req, res) => {
  const bib = db.prepare('SELECT * FROM bibliotecas WHERE id = ? AND usuario_id = ?').get(req.params.id, req.usuarioId);
  if (!bib) return res.status(404).json({ erro: 'Não encontrada' });
  if (bib.nome === 'PADRÃO') return res.status(400).json({ erro: 'Não é possível apagar a coleção padrão' });
  db.prepare('DELETE FROM bibliotecas WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.post('/api/bibliotecas/:id/itens', autenticar, (req, res) => {
  const { produto_id } = req.body;
  const bib = db.prepare('SELECT * FROM bibliotecas WHERE id = ? AND usuario_id = ?').get(req.params.id, req.usuarioId);
  if (!bib) return res.status(404).json({ erro: 'Biblioteca não encontrada' });
  db.prepare('INSERT INTO biblioteca_itens (biblioteca_id, produto_id) VALUES (?, ?)').run(req.params.id, produto_id);
  res.json({ ok: true });
});

app.delete('/api/bibliotecas/itens/:item_id', autenticar, (req, res) => {
  db.prepare('DELETE FROM biblioteca_itens WHERE id = ?').run(req.params.item_id);
  res.json({ ok: true });
});

// ─── ROTAS: CURTIDOS ─────────────────────────────────────────
app.get('/api/curtidos', autenticar, (req, res) => {
  const curtidos = db.prepare('SELECT produto_id FROM curtidos WHERE usuario_id = ?').all(req.usuarioId);
  res.json(curtidos.map(c => c.produto_id));
});

app.post('/api/curtidos/:produto_id', autenticar, (req, res) => {
  try {
    db.prepare('INSERT INTO curtidos (usuario_id, produto_id) VALUES (?, ?)').run(req.usuarioId, req.params.produto_id);
    res.json({ curtido: true });
  } catch {
    db.prepare('DELETE FROM curtidos WHERE usuario_id = ? AND produto_id = ?').run(req.usuarioId, req.params.produto_id);
    res.json({ curtido: false });
  }
});

// ─── START ────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`EIXO GARAGEM rodando na porta ${PORT}`));
