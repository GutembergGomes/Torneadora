const http = require('http')
const fs = require('fs')
const path = require('path')
const url = require('url')
const crypto = require('crypto')
let MongoClient
try { MongoClient = require('mongodb').MongoClient } catch (e) { MongoClient = null }
const MONGO_URI = process.env.MONGO_URI
const MONGO_DB = process.env.MONGO_DB || 'tornearia'
const useMongo = !!(MONGO_URI && MongoClient)
let mongo = { db: null, users: null, sessions: null, clients: null, budgets: null, materialBudgets: null }
let mongoReady = false
if (useMongo) {
  MongoClient.connect(MONGO_URI).then(client => {
    mongo.db = client.db(MONGO_DB)
    mongo.users = mongo.db.collection('users')
    mongo.sessions = mongo.db.collection('sessions')
    mongo.clients = mongo.db.collection('clients')
    mongo.budgets = mongo.db.collection('budgets')
    mongo.materialBudgets = mongo.db.collection('materialBudgets')
    mongoReady = true
  }).catch(err => { console.log('mongo', 'connect_error', err.message) })
}

const DATA_FILE = path.join(__dirname, 'data.json')
function readData(){ try{ return JSON.parse(fs.readFileSync(DATA_FILE, 'utf-8')) } catch(e){ return { users: [], sessions: [], clients: [], budgets: [], materialBudgets: [] } } }
function writeData(data){ fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2)) }

async function ensureDefaultAdmin(){
  if (useMongo) {
    if (!mongoReady) return
    const exists = await mongo.users.findOne({ email: 'admin@tornearia.local' })
    if (!exists) {
      const salt = crypto.randomBytes(16).toString('hex')
      const hash = crypto.scryptSync('admin123', salt, 64).toString('hex')
      await mongo.users.insertOne({ email: 'admin@tornearia.local', role: 'admin', salt, passwordHash: hash })
    }
    return
  }
  const data = readData()
  if (!Array.isArray(data.users)) data.users = []
  if (data.users.length === 0) {
    const salt = crypto.randomBytes(16).toString('hex')
    const hash = crypto.scryptSync('admin123', salt, 64).toString('hex')
    const admin = { id: Date.now(), email: 'admin@tornearia.local', role: 'admin', salt, passwordHash: hash }
    data.users.push(admin)
    writeData(data)
  }
}
if (useMongo) { (async () => { await new Promise(r => setTimeout(r, 500)); await ensureDefaultAdmin() })() } else { ensureDefaultAdmin() }

function createSession(userId){
  const token = crypto.randomBytes(24).toString('hex')
  const expires = Date.now() + 12 * 60 * 60 * 1000
  if (useMongo) { if (!mongoReady) return null; mongo.sessions.insertOne({ token, userId, expires }); return token }
  const data = readData()
  const session = { token, userId, expires }
  data.sessions = Array.isArray(data.sessions) ? data.sessions : []
  data.sessions.push(session)
  writeData(data)
  return token
}

function getAuthUser(req){
  const auth = req.headers['authorization'] || ''
  const parts = auth.split(' ')
  if (parts.length !== 2 || parts[0] !== 'Bearer') return null
  const token = parts[1]
  if (useMongo) {
    if (!mongoReady) return null
    return mongo.sessions.findOne({ token }).then(session => {
      if (!session) return null
      if (session.expires < Date.now()) return null
      return mongo.users.findOne({ _id: session.userId }).then(u => u || null)
    }).catch(() => null)
  }
  const data = readData()
  const session = (data.sessions||[]).find(s => s.token === token)
  if (!session) return null
  if (session.expires < Date.now()) return null
  const user = (data.users||[]).find(u => u.id === session.userId)
  return user || null
}

function requireAuth(req, res, role){
  const maybe = getAuthUser(req)
  if (maybe && typeof maybe.then === 'function') {
    return maybe.then(user => {
      if (!user) { console.log('auth', '401'); sendJson(res, 401, { error: 'não autorizado' }); return null }
      if (role && user.role !== role) { console.log('auth', '403', 'required', role, 'got', user.role); sendJson(res, 403, { error: 'proibido' }); return null }
      return user
    })
  }
  const user = maybe
  if (!user) { console.log('auth', '401'); sendJson(res, 401, { error: 'não autorizado' }); return null }
  if (role && user.role !== role) { console.log('auth', '403', 'required', role, 'got', user.role); sendJson(res, 403, { error: 'proibido' }); return null }
  return user
}

function sendJson(res, status, obj){ res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }); res.end(JSON.stringify(obj)) }
function notFound(res){ res.writeHead(404); res.end('Not Found') }
function serveStatic(req, res){ const parsed = url.parse(req.url); let filePath = path.join(__dirname, parsed.pathname === '/' ? '/index.html' : parsed.pathname); if (!filePath.startsWith(__dirname)) return notFound(res); fs.readFile(filePath, (err, content) => { if (err) return notFound(res); const ext = path.extname(filePath).toLowerCase(); const type = ext === '.html' ? 'text/html' : ext === '.css' ? 'text/css' : ext === '.js' ? 'application/javascript' : 'application/octet-stream'; res.writeHead(200, { 'Content-Type': type }); res.end(content) }) }

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true)
  console.log(new Date().toISOString(), req.method, parsed.pathname)
  if (req.method === 'OPTIONS') { res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,PATCH,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' }); return res.end() }
  if (parsed.pathname === '/api/health' && req.method === 'GET') return sendJson(res, 200, { ok: true })
  if (parsed.pathname === '/api/auth/login' && req.method === 'POST') { let body=''; req.on('data', c=> body+=c); req.on('end', async () => { try{ const p = JSON.parse(body||'{}'); if (useMongo) { if (!mongoReady) return sendJson(res, 503, { error: 'mongo indisponível' }); const user = await mongo.users.findOne({ email: (p.email||'').toLowerCase() }); if (!user) return sendJson(res, 401, { error: 'credenciais inválidas' }); const derived = crypto.scryptSync(p.password||'', user.salt, 64).toString('hex'); if (derived !== user.passwordHash) return sendJson(res, 401, { error: 'credenciais inválidas' }); const token = createSession(user._id); return sendJson(res, 200, { token, role: user.role, email: user.email }) } const data = readData(); const user = (data.users||[]).find(u => (u.email||'').toLowerCase() === (p.email||'').toLowerCase()); if (!user) return sendJson(res, 401, { error: 'credenciais inválidas' }); const derived = crypto.scryptSync(p.password||'', user.salt, 64).toString('hex'); if (derived !== user.passwordHash) return sendJson(res, 401, { error: 'credenciais inválidas' }); const token = createSession(user.id); return sendJson(res, 200, { token, role: user.role, email: user.email }) } catch(e){ return sendJson(res, 500, { error: e.message }) } }); return }
  if (parsed.pathname === '/api/auth/me' && req.method === 'GET') { const user = getAuthUser(req); if (!user) return sendJson(res, 401, { error: 'não autorizado' }); return sendJson(res, 200, { email: user.email, role: user.role }) }
  if (parsed.pathname === '/api/debug/state' && req.method === 'GET') { const user = requireAuth(req, res, 'admin'); if (!user) return; const data = readData(); return sendJson(res, 200, { users: (data.users||[]).length, sessions: (data.sessions||[]).length, clients: (data.clients||[]).length, budgets: (data.budgets||[]).length, materialBudgets: (data.materialBudgets||[]).length }) }
  if (parsed.pathname === '/api/clients' && req.method === 'GET') { const user = requireAuth(req, res); if (!user) return; if (useMongo) { if (!mongoReady) return sendJson(res, 503, { error: 'mongo indisponível' }); return mongo.clients.find({}).sort({ nome: 1 }).toArray().then(rows => sendJson(res, 200, rows)).catch(e => sendJson(res, 500, { error: e.message })) } const data = readData(); const list = data.clients.slice().sort((a,b)=> (a.nome||'').localeCompare(b.nome||'')); return sendJson(res, 200, list) }
  if (parsed.pathname === '/api/clients' && req.method === 'POST') { const user = requireAuth(req, res); if (!user) return; let body=''; req.on('data', chunk => body += chunk); req.on('end', async () => { try{ const p = JSON.parse(body||'{}'); if (!p.nome) return sendJson(res, 400, { error: 'nome obrigatório' }); if (useMongo) { if (!mongoReady) return sendJson(res, 503, { error: 'mongo indisponível' }); const found = await mongo.clients.findOne({ nome: new RegExp('^' + (p.nome||'') + '$', 'i'), empresa: new RegExp('^' + (p.empresa||'') + '$', 'i') }); if (found) return sendJson(res, 200, found); const doc = { nome: p.nome, empresa: p.empresa||null, telefone: p.telefone||null, email: p.email||null }; const ins = await mongo.clients.insertOne(doc); return sendJson(res, 200, { ...doc, _id: ins.insertedId }) } const data = readData(); const found = data.clients.find(c => (c.nome||'').toLowerCase() === (p.nome||'').toLowerCase() && (c.empresa||'').toLowerCase() === ((p.empresa||'').toLowerCase())); if (found) return sendJson(res, 200, found); const id = Date.now(); const client = { id, nome: p.nome, empresa: p.empresa||null, telefone: p.telefone||null, email: p.email||null }; data.clients.push(client); writeData(data); return sendJson(res, 200, client) } catch(e){ return sendJson(res, 500, { error: e.message }) } }); return }
  if (parsed.pathname === '/api/budgets' && req.method === 'GET') { const user = requireAuth(req, res); if (!user) return; if (useMongo) { if (!mongoReady) return sendJson(res, 503, { error: 'mongo indisponível' }); return mongo.budgets.find({}).sort({ createdAt: -1 }).toArray().then(rows => sendJson(res, 200, rows)).catch(e => sendJson(res, 500, { error: e.message })) } const data = readData(); const list = data.budgets.slice().sort((a,b)=> b.id - a.id); return sendJson(res, 200, list) }
  if (parsed.pathname === '/api/budgets' && req.method === 'POST') { const user = requireAuth(req, res); if (!user) return; let body=''; req.on('data', chunk => body += chunk); req.on('end', async () => { try{ const p = JSON.parse(body||'{}'); if (useMongo) { if (!mongoReady) return sendJson(res, 503, { error: 'mongo indisponível' }); const cliente = p.cliente || { nome: p.nome, empresa: p.empresa, telefone: p.telefone, email: p.email }; if (!cliente || !cliente.nome) return sendJson(res, 400, { error: 'cliente.nome obrigatório' }); let c = await mongo.clients.findOne({ nome: new RegExp('^' + (cliente.nome||'') + '$', 'i'), empresa: new RegExp('^' + (cliente.empresa||'') + '$', 'i') }); if (!c) { const ins = await mongo.clients.insertOne({ nome: cliente.nome, empresa: cliente.empresa||null, telefone: cliente.telefone||null, email: cliente.email||null }); c = await mongo.clients.findOne({ _id: ins.insertedId }) } const desconto = p.desconto || 0; const servicos = Array.isArray(p.servicos) ? p.servicos : []; const total = p.total || servicos.reduce((s,e)=> s + ((e.total)||((e.quantidade||0)*(e.valor||0))), 0); const valorFinal = p.valorFinal || total * (1 - desconto/100); const doc = { numero: p.numero, data: p.data, nome: c.nome, empresa: c.empresa, telefone: c.telefone, email: c.email, material: p.material||null, dimensoes: p.dimensoes||null, codigo: p.codigo||null, prazoEntrega: p.prazoEntrega||null, servicos: servicos, observacoes: p.observacoes||null, desconto, total, valorFinal, realizado: !!p.realizado, notaFiscal: p.notaFiscal||null, createdAt: new Date() }; const insB = await mongo.budgets.insertOne(doc); return sendJson(res, 200, { ...doc, _id: insB.insertedId }) } const data = readData(); const cliente = p.cliente || { nome: p.nome, empresa: p.empresa, telefone: p.telefone, email: p.email }; if (!cliente || !cliente.nome) return sendJson(res, 400, { error: 'cliente.nome obrigatório' }); let c = data.clients.find(x => (x.nome||'').toLowerCase() === (cliente.nome||'').toLowerCase() && (x.empresa||'').toLowerCase() === ((cliente.empresa||'').toLowerCase())); if (!c) { c = { id: Date.now(), nome: cliente.nome, empresa: cliente.empresa||null, telefone: cliente.telefone||null, email: cliente.email||null }; data.clients.push(c) } const id = Date.now(); const desconto = p.desconto || 0; const servicos = Array.isArray(p.servicos) ? p.servicos : []; const total = p.total || servicos.reduce((s,e)=> s + ((e.total)||((e.quantidade||0)*(e.valor||0))), 0); const valorFinal = p.valorFinal || total * (1 - desconto/100); const budget = { id, numero: p.numero, data: p.data, nome: c.nome, empresa: c.empresa, telefone: c.telefone, email: c.email, material: p.material||null, dimensoes: p.dimensoes||null, codigo: p.codigo||null, prazoEntrega: p.prazoEntrega||null, servicos: servicos, observacoes: p.observacoes||null, desconto, total, valorFinal, realizado: !!p.realizado, notaFiscal: p.notaFiscal||null }; data.budgets.push(budget); writeData(data); return sendJson(res, 200, budget) } catch(e){ return sendJson(res, 500, { error: e.message }) } }); return }
  if (parsed.pathname && parsed.pathname.startsWith('/api/budgets/') && req.method === 'PATCH') { const userMaybe = requireAuth(req, res); if (!userMaybe) return; const proceed = typeof userMaybe.then === 'function' ? userMaybe.then(u => u) : userMaybe; Promise.resolve(proceed).then(user => { if (!user) return; const idStr = parsed.pathname.split('/').pop(); let body=''; req.on('data', chunk => body += chunk); req.on('end', async () => { try{ const p = JSON.parse(body||'{}'); if ((typeof p.realizado !== 'undefined') || p.notaFiscal) { if (user.role !== 'admin') return sendJson(res, 403, { error: 'proibido' }) } if (useMongo) { if (!mongoReady) return sendJson(res, 503, { error: 'mongo indisponível' }); const filter = { _id: (() => { try { return new (require('mongodb').ObjectId)(idStr) } catch(e) { return null } })() }; if (!filter._id) return sendJson(res, 400, { error: 'id inválido' }); const update = {}; if (typeof p.realizado === 'boolean') update.realizado = p.realizado; if (p.notaFiscal) update.notaFiscal = p.notaFiscal; await mongo.budgets.updateOne(filter, { $set: update }); return sendJson(res, 200, { ok: true }) } const id = parseInt(idStr); const data = readData(); const idx = data.budgets.findIndex(b => b.id === id); if (idx < 0) return sendJson(res, 404, { error: 'não encontrado' }); if (typeof p.realizado === 'boolean') data.budgets[idx].realizado = p.realizado; if (p.notaFiscal) data.budgets[idx].notaFiscal = p.notaFiscal; writeData(data); return sendJson(res, 200, { ok: true }) } catch(e){ return sendJson(res, 500, { error: e.message }) } }) }) ; return }
  if (parsed.pathname === '/api/material-budgets' && req.method === 'GET') { const user = requireAuth(req, res); if (!user) return; if (useMongo) { if (!mongoReady) return sendJson(res, 503, { error: 'mongo indisponível' }); return mongo.materialBudgets.find({}).sort({ createdAt: -1 }).toArray().then(rows => sendJson(res, 200, rows)).catch(e => sendJson(res, 500, { error: e.message })) } const data = readData(); const list = data.materialBudgets.slice().sort((a,b)=> b.id - a.id); return sendJson(res, 200, list) }
  if (parsed.pathname === '/api/material-budgets' && req.method === 'POST') { const userMaybe = requireAuth(req, res, 'admin'); if (!userMaybe) return; const proceed = typeof userMaybe.then === 'function' ? userMaybe.then(u => u) : userMaybe; Promise.resolve(proceed).then(user => { if (!user) return; let body=''; req.on('data', chunk => body += chunk); req.on('end', async () => { try{ const p = JSON.parse(body||'{}'); if (useMongo) { if (!mongoReady) return sendJson(res, 503, { error: 'mongo indisponível' }); const doc = { numero: p.numero, data: p.data, fornecedor: p.fornecedor||{}, material: p.material||{}, condicoes: p.condicoes||{}, observacoes: p.observacoes||null, subtotalMaterial: p.subtotalMaterial||null, totalGeral: p.totalGeral||null, status: p.status||'pendente', createdAt: new Date() }; const ins = await mongo.materialBudgets.insertOne(doc); return sendJson(res, 200, { id: ins.insertedId }) } const data = readData(); const id = Date.now(); const entry = { id, numero: p.numero, data: p.data, fornecedor: p.fornecedor||{}, material: p.material||{}, condicoes: p.condicoes||{}, observacoes: p.observacoes||null, subtotalMaterial: p.subtotalMaterial||null, totalGeral: p.totalGeral||null, status: p.status||'pendente' }; data.materialBudgets.push(entry); writeData(data); return sendJson(res, 200, { id }) } catch(e){ return sendJson(res, 500, { error: e.message }) } }) }) ; return }
  return serveStatic(req, res)
})

const PORT = process.env.PORT || 3000
server.listen(PORT, () => { console.log('Servidor iniciado em http://localhost:' + PORT) })