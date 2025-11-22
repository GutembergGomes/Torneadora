const http = require('http')
const fs = require('fs')
const path = require('path')
const url = require('url')
const crypto = require('crypto')
const https = require('https')
let createSupabaseClient
try { createSupabaseClient = require('@supabase/supabase-js').createClient } catch (e) { createSupabaseClient = null }
let nodemailer
try { nodemailer = require('nodemailer') } catch (e) { nodemailer = null }
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
const SUPABASE_URL = process.env.SUPABASE_URL
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE || process.env.SUPABASE_KEY
const supabaseClientAvailable = !!(createSupabaseClient && SUPABASE_URL && SUPABASE_KEY)
const useSupabase = !!(SUPABASE_URL && SUPABASE_KEY)
const supabase = supabaseClientAvailable ? createSupabaseClient(SUPABASE_URL, SUPABASE_KEY) : null

function sbRest(method, table, query, body){
  return new Promise((resolve, reject) => {
    try{
      const u = new URL((SUPABASE_URL||'').replace(/\/$/, '') + '/rest/v1/' + table)
      if (query && typeof query === 'object') {
        Object.keys(query).forEach(k => u.searchParams.append(k, query[k]))
      }
      const opts = { method, headers: { 'apikey': SUPABASE_KEY, 'Authorization': 'Bearer ' + SUPABASE_KEY, 'Content-Type': 'application/json', 'Accept': 'application/json', 'Prefer': 'return=representation' } }
      const req = https.request(u, opts, res => { let data=''; res.on('data', d => data += d); res.on('end', () => { let json=null; try{ json = data ? JSON.parse(data) : null }catch(e){}; if (res.statusCode >= 200 && res.statusCode < 300) return resolve(json); const msg = (json && (json.message||json.error)) || ('HTTP ' + res.statusCode); return reject(new Error(msg)) }) })
      req.on('error', reject)
      if (body) req.write(JSON.stringify(body))
      req.end()
    }catch(e){ reject(e) }
  })
}
async function sbFindOne(table, filters){ const q = { select: '*', limit: '1' }; Object.keys(filters||{}).forEach(k => { q[k] = 'eq.' + filters[k] }); const res = await sbRest('GET', table, q); return Array.isArray(res) && res.length ? res[0] : null }
async function sbInsert(table, obj){ const res = await sbRest('POST', table, { select: '*' }, obj); return Array.isArray(res) ? res[0] : res }
async function sbUpdate(table, filters, obj){ const q = {}; Object.keys(filters||{}).forEach(k => { q[k] = 'eq.' + filters[k] }); const res = await sbRest('PATCH', table, { ...q, select: '*' }, obj); return Array.isArray(res) ? res[0] : res }
function genToken(bytes = 24){ return crypto.randomBytes(bytes).toString('hex') }
const APP_BASE_URL = process.env.APP_BASE_URL || process.env.RENDER_EXTERNAL_URL || ('http://localhost:' + (process.env.PORT || 3000))
const SMTP_HOST = process.env.SMTP_HOST || ''
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '0', 10)
const SMTP_SECURE = (process.env.SMTP_SECURE || 'false').toLowerCase() === 'true'
const SMTP_USER = process.env.SMTP_USER || ''
const SMTP_PASS = process.env.SMTP_PASS || ''
const SMTP_FROM = process.env.SMTP_FROM || ''

async function sendConfirmationEmail(to, link){
  if (!nodemailer || !SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS || !SMTP_FROM) {
    console.log('confirm', link)
    return { sent: false }
  }
  try{
    const transporter = nodemailer.createTransport({ host: SMTP_HOST, port: SMTP_PORT, secure: SMTP_SECURE, auth: { user: SMTP_USER, pass: SMTP_PASS } })
    const info = await transporter.sendMail({ from: SMTP_FROM, to, subject: 'Confirme seu cadastro', text: `Finalize seu cadastro clicando: ${link}` })
    return { sent: true, messageId: info.messageId }
  }catch(e){
    console.log('email_error', e.message)
    console.log('confirm', link)
    return { sent: false, error: e.message }
  }
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
      await mongo.users.insertOne({ email: 'admin@tornearia.local', role: 'admin', salt, passwordHash: hash, verified: true, createdAt: new Date() })
    }
    return
  }
  if (useSupabase) {
    const exists = supabaseClientAvailable
      ? (await supabase.from('users').select('id').eq('email', 'admin@tornearia.local').limit(1).maybeSingle()).data
      : (await sbFindOne('users', { email: 'admin@tornearia.local' }))
    if (!exists) {
      const salt = crypto.randomBytes(16).toString('hex')
      const hash = crypto.scryptSync('admin123', salt, 64).toString('hex')
      if (supabaseClientAvailable) {
        await supabase.from('users').insert({ email: 'admin@tornearia.local', role: 'admin', salt, password_hash: hash, verified: true, created_at: new Date().toISOString() })
      } else {
        await sbInsert('users', { email: 'admin@tornearia.local', role: 'admin', salt, password_hash: hash, verified: true, created_at: new Date().toISOString() })
      }
    }
    return
  }
  const data = readData()
  if (!Array.isArray(data.users)) data.users = []
  if (data.users.length === 0) {
    const salt = crypto.randomBytes(16).toString('hex')
    const hash = crypto.scryptSync('admin123', salt, 64).toString('hex')
    const admin = { id: Date.now(), email: 'admin@tornearia.local', role: 'admin', salt, passwordHash: hash, verified: true, createdAt: Date.now() }
    data.users.push(admin)
    writeData(data)
  }
}
if (useMongo) { (async () => { await new Promise(r => setTimeout(r, 500)); await ensureDefaultAdmin() })() } else { ensureDefaultAdmin() }

function createSession(userId){
  const token = crypto.randomBytes(24).toString('hex')
  const expires = Date.now() + 12 * 60 * 60 * 1000
  if (useSupabase) { if (supabaseClientAvailable) { supabase.from('sessions').insert({ token, user_id: userId, expires }); } else { sbInsert('sessions', { token, user_id: userId, expires }).catch(()=>{}) } return token }
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
  if (useSupabase) {
    if (supabaseClientAvailable) {
      return supabase.from('sessions').select('*').eq('token', token).limit(1).maybeSingle().then(async ({ data: session }) => {
        if (!session) return null
        if (session.expires < Date.now()) return null
        const { data: user } = await supabase.from('users').select('*').eq('id', session.user_id).limit(1).maybeSingle()
        return user ? { id: user.id, email: user.email, role: user.role } : null
      }).catch(() => null)
    } else {
      return sbFindOne('sessions', { token }).then(async (session) => {
        if (!session) return null
        if (session.expires < Date.now()) return null
        const user = await sbFindOne('users', { id: session.user_id })
        return user ? { id: user.id, email: user.email, role: user.role } : null
      }).catch(() => null)
    }
  }
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
  if (req.method === 'OPTIONS') { res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,PATCH,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization' }); return res.end() }
  if (parsed.pathname === '/api/health' && req.method === 'GET') { const mode = useSupabase ? 'supabase' : (useMongo ? 'mongo' : 'file'); return sendJson(res, 200, { ok: true, mode }) }
  if (parsed.pathname === '/env.js' && req.method === 'GET') { const base = process.env.APP_BASE_URL || (`http://${req.headers.host}`); const js = `window.API_URL=${JSON.stringify(base)};`; res.writeHead(200, { 'Content-Type': 'application/javascript' }); return res.end(js) }
  if (parsed.pathname === '/api/auth/register' && req.method === 'POST') { let body=''; req.on('data', c=> body+=c); req.on('end', async () => { try{ const p = JSON.parse(body||'{}'); const email = (p.email||'').toLowerCase().trim(); const password = (p.password||'').trim(); if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return sendJson(res, 400, { error: 'email inválido' }); if (!password || password.length < 6) return sendJson(res, 400, { error: 'senha muito curta' }); const salt = crypto.randomBytes(16).toString('hex'); const hash = crypto.scryptSync(password, salt, 64).toString('hex'); const confirmToken = genToken(24); const confirmLink = `${APP_BASE_URL}/api/auth/confirm?token=${confirmToken}`; if (useSupabase) { const exists = supabaseClientAvailable ? (await supabase.from('users').select('id').eq('email', email).limit(1).maybeSingle()) : { data: await sbFindOne('users', { email }) }; if (exists.error) return sendJson(res, 500, { error: exists.error.message }); if (exists.data) return sendJson(res, 409, { error: 'email já cadastrado' }); if (supabaseClientAvailable) { const ins = await supabase.from('users').insert({ email, role: 'user', salt, password_hash: hash, verified: false, confirm_token: confirmToken, created_at: new Date().toISOString() }).select('id').maybeSingle(); if (ins.error) return sendJson(res, 500, { error: ins.error.message }) } else { await sbInsert('users', { email, role: 'user', salt, password_hash: hash, verified: false, confirm_token: confirmToken, created_at: new Date().toISOString() }) } const mail = await sendConfirmationEmail(email, confirmLink); return sendJson(res, 200, { ok: true, confirmLink: mail.sent ? undefined : confirmLink, hint: mail.sent ? undefined : 'E-mail não enviado; use o link' }) } if (useMongo) { if (!mongoReady) return sendJson(res, 503, { error: 'mongo indisponível' }); const exists = await mongo.users.findOne({ email }); if (exists) return sendJson(res, 409, { error: 'email já cadastrado' }); await mongo.users.insertOne({ email, role: 'user', salt, passwordHash: hash, verified: false, confirmToken, createdAt: new Date() }); const mail = await sendConfirmationEmail(email, confirmLink); return sendJson(res, 200, { ok: true, confirmLink: mail.sent ? undefined : confirmLink, hint: mail.sent ? undefined : 'E-mail não enviado; use o link' }) } const data = readData(); data.users = Array.isArray(data.users) ? data.users : []; const exists = data.users.find(u => (u.email||'').toLowerCase() === email); if (exists) return sendJson(res, 409, { error: 'email já cadastrado' }); const id = Date.now(); data.users.push({ id, email, role: 'user', salt, passwordHash: hash, verified: false, confirmToken, createdAt: Date.now() }); writeData(data); const mail = await sendConfirmationEmail(email, confirmLink); return sendJson(res, 200, { ok: true, confirmLink: mail.sent ? undefined : confirmLink, hint: mail.sent ? undefined : 'E-mail não enviado; use o link' }) } catch(e){ return sendJson(res, 500, { error: e.message }) } }); return }
  if (parsed.pathname === '/api/auth/confirm' && req.method === 'GET') { const token = (parsed.query && parsed.query.token) || null; if (!token) return sendJson(res, 400, { error: 'token obrigatório' }); if (useSupabase) { if (supabaseClientAvailable) { return supabase.from('users').select('id').eq('confirm_token', token).limit(1).maybeSingle().then(({ data: u, error }) => { if (error) return sendJson(res, 500, { error: error.message }); if (!u) return sendJson(res, 404, { error: 'token inválido' }); return supabase.from('users').update({ verified: true, confirm_token: null }).eq('id', u.id).then(() => sendJson(res, 200, { ok: true })).catch(e => sendJson(res, 500, { error: e.message })) }).catch(e => sendJson(res, 500, { error: e.message })) } else { return sbFindOne('users', { confirm_token: token }).then(u => { if (!u) return sendJson(res, 404, { error: 'token inválido' }); return sbUpdate('users', { id: u.id }, { verified: true, confirm_token: null }).then(() => sendJson(res, 200, { ok: true })).catch(e => sendJson(res, 500, { error: e.message })) }).catch(e => sendJson(res, 500, { error: e.message })) } } if (useMongo) { if (!mongoReady) return sendJson(res, 503, { error: 'mongo indisponível' }); return mongo.users.findOne({ confirmToken: token }).then(async u => { if (!u) return sendJson(res, 404, { error: 'token inválido' }); await mongo.users.updateOne({ _id: u._id }, { $set: { verified: true }, $unset: { confirmToken: '' } }); return sendJson(res, 200, { ok: true }) }).catch(e => sendJson(res, 500, { error: e.message })) } const data = readData(); const idx = (data.users||[]).findIndex(u => u.confirmToken === token); if (idx < 0) return sendJson(res, 404, { error: 'token inválido' }); data.users[idx].verified = true; data.users[idx].confirmToken = null; writeData(data); return sendJson(res, 200, { ok: true }) }
  if (parsed.pathname === '/api/auth/login' && req.method === 'POST') { let body=''; req.on('data', c=> body+=c); req.on('end', async () => { try{ const p = JSON.parse(body||'{}'); if (useSupabase) { const user = supabaseClientAvailable ? (await supabase.from('users').select('*').eq('email', (p.email||'').toLowerCase()).limit(1).maybeSingle()).data : (await sbFindOne('users', { email: (p.email||'').toLowerCase() })); if (!user) return sendJson(res, 401, { error: 'credenciais inválidas' }); const derived = crypto.scryptSync(p.password||'', user.salt, 64).toString('hex'); if (derived !== (user.password_hash||user.passwordHash)) return sendJson(res, 401, { error: 'credenciais inválidas' }); if (!user.verified) return sendJson(res, 403, { error: 'confirme seu email' }); const token = createSession(user.id); return sendJson(res, 200, { token, role: user.role, email: user.email }) } if (useMongo) { if (!mongoReady) return sendJson(res, 503, { error: 'mongo indisponível' }); const user = await mongo.users.findOne({ email: (p.email||'').toLowerCase() }); if (!user) return sendJson(res, 401, { error: 'credenciais inválidas' }); const derived = crypto.scryptSync(p.password||'', user.salt, 64).toString('hex'); if (derived !== user.passwordHash) return sendJson(res, 401, { error: 'credenciais inválidas' }); if (!user.verified) return sendJson(res, 403, { error: 'confirme seu email' }); const token = createSession(user._id); return sendJson(res, 200, { token, role: user.role, email: user.email }) } const data = readData(); const user = (data.users||[]).find(u => (u.email||'').toLowerCase() === (p.email||'').toLowerCase()); if (!user) return sendJson(res, 401, { error: 'credenciais inválidas' }); const derived = crypto.scryptSync(p.password||'', user.salt, 64).toString('hex'); if (derived !== user.passwordHash) return sendJson(res, 401, { error: 'credenciais inválidas' }); if (!user.verified) return sendJson(res, 403, { error: 'confirme seu email' }); const token = createSession(user.id); return sendJson(res, 200, { token, role: user.role, email: user.email }) } catch(e){ return sendJson(res, 500, { error: e.message }) } }); return }
  if (parsed.pathname === '/api/auth/me' && req.method === 'GET') { const user = getAuthUser(req); if (!user) return sendJson(res, 401, { error: 'não autorizado' }); return sendJson(res, 200, { email: user.email, role: user.role }) }
  if (parsed.pathname === '/api/debug/state' && req.method === 'GET') { const user = requireAuth(req, res, 'admin'); if (!user) return; const data = readData(); return sendJson(res, 200, { users: (data.users||[]).length, sessions: (data.sessions||[]).length, clients: (data.clients||[]).length, budgets: (data.budgets||[]).length, materialBudgets: (data.materialBudgets||[]).length }) }
  if (parsed.pathname === '/api/clients' && req.method === 'GET') { const user = requireAuth(req, res); if (!user) return; if (useSupabase) { if (supabaseClientAvailable) { return supabase.from('clients').select('*').order('nome', { ascending: true }).then(({ data, error }) => { if (error) return sendJson(res, 500, { error: error.message }); return sendJson(res, 200, data||[]) }) } else { return sbRest('GET', 'clients', { select: '*', order: 'nome.asc' }).then(data => sendJson(res, 200, data||[])).catch(e => sendJson(res, 500, { error: e.message })) } } if (useMongo) { if (!mongoReady) return sendJson(res, 503, { error: 'mongo indisponível' }); return mongo.clients.find({}).sort({ nome: 1 }).toArray().then(rows => sendJson(res, 200, rows)).catch(e => sendJson(res, 500, { error: e.message })) } const data = readData(); const list = data.clients.slice().sort((a,b)=> (a.nome||'').localeCompare(b.nome||'')); return sendJson(res, 200, list) }
  if (parsed.pathname === '/api/clients' && req.method === 'POST') { const user = requireAuth(req, res); if (!user) return; let body=''; req.on('data', chunk => body += chunk); req.on('end', async () => { try{ const p = JSON.parse(body||'{}'); if (!p.nome) return sendJson(res, 400, { error: 'nome obrigatório' }); if (useSupabase) { if (supabaseClientAvailable) { const { data: found } = await supabase.from('clients').select('*').eq('nome', p.nome).eq('empresa', p.empresa||null).limit(1).maybeSingle(); if (found) return sendJson(res, 200, found); const doc = { nome: p.nome, empresa: p.empresa||null, telefone: p.telefone||null, email: p.email||null }; const ins = await supabase.from('clients').insert(doc).select('*').maybeSingle(); return sendJson(res, 200, ins.data || doc) } else { const found = await sbFindOne('clients', { nome: p.nome, empresa: (p.empresa||null) }); if (found) return sendJson(res, 200, found); const doc = { nome: p.nome, empresa: p.empresa||null, telefone: p.telefone||null, email: p.email||null }; const ins = await sbInsert('clients', doc); return sendJson(res, 200, ins || doc) } } if (useMongo) { if (!mongoReady) return sendJson(res, 503, { error: 'mongo indisponível' }); const found = await mongo.clients.findOne({ nome: new RegExp('^' + (p.nome||'') + '$', 'i'), empresa: new RegExp('^' + (p.empresa||'') + '$', 'i') }); if (found) return sendJson(res, 200, found); const doc = { nome: p.nome, empresa: p.empresa||null, telefone: p.telefone||null, email: p.email||null }; const ins = await mongo.clients.insertOne(doc); return sendJson(res, 200, { ...doc, _id: ins.insertedId }) } const data = readData(); const found = data.clients.find(c => (c.nome||'').toLowerCase() === (p.nome||'').toLowerCase() && (c.empresa||'').toLowerCase() === ((p.empresa||'').toLowerCase())); if (found) return sendJson(res, 200, found); const id = Date.now(); const client = { id, nome: p.nome, empresa: p.empresa||null, telefone: p.telefone||null, email: p.email||null }; data.clients.push(client); writeData(data); return sendJson(res, 200, client) } catch(e){ return sendJson(res, 500, { error: e.message }) } }); return }
  if (parsed.pathname === '/api/budgets' && req.method === 'GET') { const user = requireAuth(req, res); if (!user) return; if (useSupabase) { if (supabaseClientAvailable) { return supabase.from('budgets').select('*').order('created_at', { ascending: false }).then(({ data, error }) => { if (error) return sendJson(res, 500, { error: error.message }); return sendJson(res, 200, data||[]) }) } else { return sbRest('GET', 'budgets', { select: '*', order: 'created_at.desc' }).then(data => sendJson(res, 200, data||[])).catch(e => sendJson(res, 500, { error: e.message })) } } if (useMongo) { if (!mongoReady) return sendJson(res, 503, { error: 'mongo indisponível' }); return mongo.budgets.find({}).sort({ createdAt: -1 }).toArray().then(rows => sendJson(res, 200, rows)).catch(e => sendJson(res, 500, { error: e.message })) } const data = readData(); const list = data.budgets.slice().sort((a,b)=> b.id - a.id); return sendJson(res, 200, list) }
  if (parsed.pathname === '/api/budgets' && req.method === 'POST') { const user = requireAuth(req, res); if (!user) return; let body=''; req.on('data', chunk => body += chunk); req.on('end', async () => { try{ const p = JSON.parse(body||'{}'); if (useSupabase) { const cliente = p.cliente || { nome: p.nome, empresa: p.empresa, telefone: p.telefone, email: p.email }; if (!cliente || !cliente.nome) return sendJson(res, 400, { error: 'cliente.nome obrigatório' }); let c; if (supabaseClientAvailable) { const r = await supabase.from('clients').select('*').eq('nome', cliente.nome).eq('empresa', cliente.empresa||null).limit(1).maybeSingle(); c = r.data } else { c = await sbFindOne('clients', { nome: cliente.nome, empresa: (cliente.empresa||null) }) } if (!c) { const newClient = { nome: cliente.nome, empresa: cliente.empresa||null, telefone: cliente.telefone||null, email: cliente.email||null }; c = supabaseClientAvailable ? (await supabase.from('clients').insert(newClient).select('*').maybeSingle()).data : (await sbInsert('clients', newClient)) } const desconto = p.desconto || 0; const servicos = Array.isArray(p.servicos) ? p.servicos : []; const total = p.total || servicos.reduce((s,e)=> s + ((e.total)||((e.quantidade||0)*(e.valor||0))), 0); const valorFinal = p.valorFinal || total * (1 - desconto/100); const doc = { numero: p.numero, data: p.data, nome: c.nome, empresa: c.empresa, telefone: c.telefone, email: c.email, material: p.material||null, dimensoes: p.dimensoes||null, codigo: p.codigo||null, prazo_entrega: p.prazoEntrega||null, servicos: servicos, observacoes: p.observacoes||null, desconto, total, valor_final: valorFinal, realizado: !!p.realizado, nota_fiscal: p.notaFiscal||null, created_at: new Date().toISOString() }; const insB = supabaseClientAvailable ? (await supabase.from('budgets').insert(doc).select('*').maybeSingle()).data : (await sbInsert('budgets', doc)); return sendJson(res, 200, insB || doc) } if (useMongo) { if (!mongoReady) return sendJson(res, 503, { error: 'mongo indisponível' }); const cliente = p.cliente || { nome: p.nome, empresa: p.empresa, telefone: p.telefone, email: p.email }; if (!cliente || !cliente.nome) return sendJson(res, 400, { error: 'cliente.nome obrigatório' }); let c = await mongo.clients.findOne({ nome: new RegExp('^' + (cliente.nome||'') + '$', 'i'), empresa: new RegExp('^' + (cliente.empresa||'') + '$', 'i') }); if (!c) { const ins = await mongo.clients.insertOne({ nome: cliente.nome, empresa: cliente.empresa||null, telefone: cliente.telefone||null, email: cliente.email||null }); c = await mongo.clients.findOne({ _id: ins.insertedId }) } const desconto = p.desconto || 0; const servicos = Array.isArray(p.servicos) ? p.servicos : []; const total = p.total || servicos.reduce((s,e)=> s + ((e.total)||((e.quantidade||0)*(e.valor||0))), 0); const valorFinal = p.valorFinal || total * (1 - desconto/100); const doc = { numero: p.numero, data: p.data, nome: c.nome, empresa: c.empresa, telefone: c.telefone, email: c.email, material: p.material||null, dimensoes: p.dimensoes||null, codigo: p.codigo||null, prazoEntrega: p.prazoEntrega||null, servicos: servicos, observacoes: p.observacoes||null, desconto, total, valorFinal, realizado: !!p.realizado, notaFiscal: p.notaFiscal||null, createdAt: new Date() }; const insB = await mongo.budgets.insertOne(doc); return sendJson(res, 200, { ...doc, _id: insB.insertedId }) } const data = readData(); const cliente = p.cliente || { nome: p.nome, empresa: p.empresa, telefone: p.telefone, email: p.email }; if (!cliente || !cliente.nome) return sendJson(res, 400, { error: 'cliente.nome obrigatório' }); let c = data.clients.find(x => (x.nome||'').toLowerCase() === (cliente.nome||'').toLowerCase() && (x.empresa||'').toLowerCase() === ((cliente.empresa||'').toLowerCase())); if (!c) { c = { id: Date.now(), nome: cliente.nome, empresa: cliente.empresa||null, telefone: cliente.telefone||null, email: cliente.email||null }; data.clients.push(c) } const id = Date.now(); const desconto = p.desconto || 0; const servicos = Array.isArray(p.servicos) ? p.servicos : []; const total = p.total || servicos.reduce((s,e)=> s + ((e.total)||((e.quantidade||0)*(e.valor||0))), 0); const valorFinal = p.valorFinal || total * (1 - desconto/100); const budget = { id, numero: p.numero, data: p.data, nome: c.nome, empresa: c.empresa, telefone: c.telefone, email: c.email, material: p.material||null, dimensoes: p.dimensoes||null, codigo: p.codigo||null, prazoEntrega: p.prazoEntrega||null, servicos: servicos, observacoes: p.observacoes||null, desconto, total, valorFinal, realizado: !!p.realizado, notaFiscal: p.notaFiscal||null }; data.budgets.push(budget); writeData(data); return sendJson(res, 200, budget) } catch(e){ return sendJson(res, 500, { error: e.message }) } }); return }
  if (parsed.pathname && parsed.pathname.startsWith('/api/budgets/') && req.method === 'PATCH') { const userMaybe = requireAuth(req, res); if (!userMaybe) return; const proceed = typeof userMaybe.then === 'function' ? userMaybe.then(u => u) : userMaybe; Promise.resolve(proceed).then(user => { if (!user) return; const idStr = parsed.pathname.split('/').pop(); let body=''; req.on('data', chunk => body += chunk); req.on('end', async () => { try{ const p = JSON.parse(body||'{}'); if ((typeof p.realizado !== 'undefined') || p.notaFiscal) { if (user.role !== 'admin') return sendJson(res, 403, { error: 'proibido' }) } if (useSupabase) { const update = {}; if (typeof p.realizado === 'boolean') update.realizado = p.realizado; if (p.notaFiscal) update.nota_fiscal = p.notaFiscal; await supabase.from('budgets').update(update).eq('id', idStr); return sendJson(res, 200, { ok: true }) } if (useMongo) { if (!mongoReady) return sendJson(res, 503, { error: 'mongo indisponível' }); const filter = { _id: (() => { try { return new (require('mongodb').ObjectId)(idStr) } catch(e) { return null } })() }; if (!filter._id) return sendJson(res, 400, { error: 'id inválido' }); const update = {}; if (typeof p.realizado === 'boolean') update.realizado = p.realizado; if (p.notaFiscal) update.notaFiscal = p.notaFiscal; await mongo.budgets.updateOne(filter, { $set: update }); return sendJson(res, 200, { ok: true }) } const id = parseInt(idStr); const data = readData(); const idx = data.budgets.findIndex(b => b.id === id); if (idx < 0) return sendJson(res, 404, { error: 'não encontrado' }); if (typeof p.realizado === 'boolean') data.budgets[idx].realizado = p.realizado; if (p.notaFiscal) data.budgets[idx].notaFiscal = p.notaFiscal; writeData(data); return sendJson(res, 200, { ok: true }) } catch(e){ return sendJson(res, 500, { error: e.message }) } }) }) ; return }
  if (parsed.pathname === '/api/material-budgets' && req.method === 'GET') { const user = requireAuth(req, res); if (!user) return; if (useSupabase) { if (supabaseClientAvailable) { return supabase.from('material_budgets').select('*').order('created_at', { ascending: false }).then(({ data, error }) => { if (error) return sendJson(res, 500, { error: error.message }); return sendJson(res, 200, data||[]) }) } else { return sbRest('GET', 'material_budgets', { select: '*', order: 'created_at.desc' }).then(data => sendJson(res, 200, data||[])).catch(e => sendJson(res, 500, { error: e.message })) } } if (useMongo) { if (!mongoReady) return sendJson(res, 503, { error: 'mongo indisponível' }); return mongo.materialBudgets.find({}).sort({ createdAt: -1 }).toArray().then(rows => sendJson(res, 200, rows)).catch(e => sendJson(res, 500, { error: e.message })) } const data = readData(); const list = data.materialBudgets.slice().sort((a,b)=> b.id - a.id); return sendJson(res, 200, list) }
  if (parsed.pathname === '/api/material-budgets' && req.method === 'POST') { const userMaybe = requireAuth(req, res, 'admin'); if (!userMaybe) return; const proceed = typeof userMaybe.then === 'function' ? userMaybe.then(u => u) : userMaybe; Promise.resolve(proceed).then(user => { if (!user) return; let body=''; req.on('data', chunk => body += chunk); req.on('end', async () => { try{ const p = JSON.parse(body||'{}'); if (useSupabase) { const doc = { numero: p.numero, data: p.data, fornecedor: p.fornecedor||{}, material: p.material||{}, condicoes: p.condicoes||{}, observacoes: p.observacoes||null, subtotal_material: p.subtotalMaterial||null, total_geral: p.totalGeral||null, status: p.status||'pendente', created_at: new Date().toISOString() }; const ins = supabaseClientAvailable ? (await supabase.from('material_budgets').insert(doc).select('id').maybeSingle()).data : (await sbInsert('material_budgets', doc)); return sendJson(res, 200, { id: (ins && ins.id) || null }) } if (useMongo) { if (!mongoReady) return sendJson(res, 503, { error: 'mongo indisponível' }); const doc = { numero: p.numero, data: p.data, fornecedor: p.fornecedor||{}, material: p.material||{}, condicoes: p.condicoes||{}, observacoes: p.observacoes||null, subtotalMaterial: p.subtotalMaterial||null, totalGeral: p.totalGeral||null, status: p.status||'pendente', createdAt: new Date() }; const ins = await mongo.materialBudgets.insertOne(doc); return sendJson(res, 200, { id: ins.insertedId }) } const data = readData(); const id = Date.now(); const entry = { id, numero: p.numero, data: p.data, fornecedor: p.fornecedor||{}, material: p.material||{}, condicoes: p.condicoes||{}, observacoes: p.observacoes||null, subtotalMaterial: p.subtotalMaterial||null, totalGeral: p.totalGeral||null, status: p.status||'pendente' }; data.materialBudgets.push(entry); writeData(data); return sendJson(res, 200, { id }) } catch(e){ return sendJson(res, 500, { error: e.message }) } }) }) ; return }
  return serveStatic(req, res)
})

const PORT = process.env.PORT || 3000
server.listen(PORT, () => { console.log('Servidor iniciado em http://localhost:' + PORT) })