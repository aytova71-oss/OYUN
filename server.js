// Asılılıqsız Node.js server (Node 18+). Google və Facebook ilə giriş + hesab yedəyi.
// İşə sal:  node server.js   (mühit dəyişənləri üçün README.md-ə bax)
const http = require('http'), https = require('https'), fs = require('fs'), crypto = require('crypto');
const E = process.env;
const PORT = +E.PORT || 3000;
const BASE = (E.PUBLIC_URL || 'http://localhost:' + PORT).replace(/\/$/, '');   // bu serverin açıq ünvanı
const ALLOWED = (E.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean); // oyunun ünvanı(ları)
const SECRET = E.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const DB = E.DB_FILE || './data.json';
let db = { users: {}, saves: {} };
try { db = JSON.parse(fs.readFileSync(DB, 'utf8')); } catch (e) {}
const persist = () => fs.writeFile(DB, JSON.stringify(db), () => {});

const P = {
  google: { id: E.GOOGLE_CLIENT_ID, sec: E.GOOGLE_CLIENT_SECRET,
    auth: 'https://accounts.google.com/o/oauth2/v2/auth', tok: 'https://oauth2.googleapis.com/token',
    me: 'https://openidconnect.googleapis.com/v1/userinfo', scope: 'openid email profile' },
  facebook: { id: E.FACEBOOK_APP_ID, sec: E.FACEBOOK_APP_SECRET,
    auth: 'https://www.facebook.com/v19.0/dialog/oauth', tok: 'https://graph.facebook.com/v19.0/oauth/access_token',
    me: 'https://graph.facebook.com/me?fields=id,name,email', scope: 'public_profile,email' }
};

const b64 = b => Buffer.from(b).toString('base64url');
const sign = s => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
const mk = (o, ttl) => { const p = b64(JSON.stringify({ ...o, exp: Date.now() + ttl })); return p + '.' + sign(p); };
function ck(t) {
  if (typeof t !== 'string') return null; const [p, s] = t.split('.');
  if (!p || !s || sign(p) !== s) return null;
  try { const o = JSON.parse(Buffer.from(p, 'base64url')); return o.exp > Date.now() ? o : null; } catch (e) { return null; }
}
function okReturn(u) { try { const o = new URL(u).origin; return ALLOWED.includes('*') || ALLOWED.includes(o); } catch (e) { return false; } }
function req(url, opt, body) {
  return new Promise((res, rej) => {
    const r = https.request(url, opt, x => { let d = ''; x.on('data', c => d += c); x.on('end', () => { try { res(JSON.parse(d)); } catch (e) { rej(e); } }); });
    r.on('error', rej); if (body) r.write(body); r.end();
  });
}
function cors(rq, rs) {
  const o = rq.headers.origin;
  if (o && (ALLOWED.includes('*') || ALLOWED.includes(o))) rs.setHeader('Access-Control-Allow-Origin', o);
  rs.setHeader('Access-Control-Allow-Headers', 'Authorization,Content-Type');
  rs.setHeader('Access-Control-Allow-Methods', 'GET,PUT,OPTIONS'); rs.setHeader('Vary', 'Origin');
}
const json = (rs, c, o) => { rs.writeHead(c, { 'Content-Type': 'application/json' }); rs.end(JSON.stringify(o)); };
const pub = u => ({ id: u.id, name: u.name, email: u.email || '', google: !!u.google, facebook: !!u.facebook, fbName: u.fbName || '' });

http.createServer(async (rq, rs) => {
  cors(rq, rs);
  if (rq.method === 'OPTIONS') { rs.writeHead(204); return rs.end(); }
  const u = new URL(rq.url, BASE), m = /^\/auth\/(google|facebook)(\/callback)?$/.exec(u.pathname);
  try {
    if (m) {
      const pr = P[m[1]], redirect = BASE + '/auth/' + m[1] + '/callback';
      if (!pr.id || !pr.sec) { rs.writeHead(500); return rs.end(m[1] + ' açarları təyin olunmayıb.'); }
      if (!m[2]) {
        const back = u.searchParams.get('return') || '';
        if (!okReturn(back)) { rs.writeHead(400); return rs.end('return ünvanı icazəli deyil (ALLOWED_ORIGINS).'); }
        const link = u.searchParams.get('link') || '';                 // mövcud hesaba bağlamaq üçün
        const st = mk({ back, link, n: crypto.randomBytes(6).toString('hex') }, 10 * 60e3);
        const q = new URLSearchParams({ client_id: pr.id, redirect_uri: redirect, response_type: 'code', scope: pr.scope, state: st });
        rs.writeHead(302, { Location: pr.auth + '?' + q }); return rs.end();
      }
      const st = ck(u.searchParams.get('state'));
      if (!st || !u.searchParams.get('code')) { rs.writeHead(400); return rs.end('Giriş ləğv olundu və ya vaxt bitdi.'); }
      const form = new URLSearchParams({ code: u.searchParams.get('code'), client_id: pr.id, client_secret: pr.sec, redirect_uri: redirect, grant_type: 'authorization_code' }).toString();
      const t = await req(pr.tok, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }, form);
      if (!t.access_token) { rs.writeHead(400); return rs.end('Token alınmadı.'); }
      const me = await req(pr.me, { headers: { Authorization: 'Bearer ' + t.access_token } });
      const pid = String(me.sub || me.id || ''); if (!pid) { rs.writeHead(400); return rs.end('Profil alınmadı.'); }
      const key = m[1] + ':' + pid, cur = ck(st.link);
      let uid = Object.keys(db.users).find(k => db.users[k][m[1]] === pid);
      if (cur && db.users[cur.uid]) {                                   // bu giriş mövcud hesaba bağlanır
        if (uid && uid !== cur.uid) { rs.writeHead(409); return rs.end('Bu hesab artıq başqa oyunçuya bağlıdır.'); }
        uid = cur.uid;
      }
      if (!uid) { uid = crypto.randomBytes(8).toString('hex'); db.users[uid] = { id: uid, name: String(me.name || 'Oyunçu').slice(0, 30) }; }
      const us = db.users[uid]; us[m[1]] = pid;
      if (m[1] === 'google') us.email = me.email || us.email; else { us.fbName = String(me.name || '').slice(0, 40); us.email = us.email || me.email; }
      persist();
      const tok = mk({ uid }, 90 * 24 * 3600e3);
      rs.writeHead(302, { Location: st.back.split('#')[0] + '#auth=' + tok }); return rs.end();
    }
    const a = ck((rq.headers.authorization || '').replace(/^Bearer /, '')), us = a && db.users[a.uid];
    if (u.pathname === '/api/me' && rq.method === 'GET') return us ? json(rs, 200, { user: pub(us), hasSave: !!db.saves[us.id], linkToken: mk({ uid: us.id }, 10 * 60e3) }) : json(rs, 401, { error: 'auth' });
    if (u.pathname === '/api/save') {
      if (!us) return json(rs, 401, { error: 'auth' });
      if (rq.method === 'GET') return json(rs, 200, db.saves[us.id] || null);
      if (rq.method === 'PUT') {
        let d = ''; rq.on('data', c => { d += c; if (d.length > 3e6) rq.destroy(); });
        rq.on('end', () => { try { const o = JSON.parse(d); if (typeof o.c !== 'string') throw 0; db.saves[us.id] = { c: o.c, t: Date.now() }; persist(); json(rs, 200, { ok: 1 }); } catch (e) { json(rs, 400, { error: 'bad' }); } });
        return;
      }
    }
    if (u.pathname === '/' || u.pathname === '/privacy') {
      const priv = u.pathname === '/privacy';
      rs.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return rs.end('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Oyun</title><body style="font:16px/1.6 sans-serif;max-width:640px;margin:30px auto;padding:0 16px">' + (priv
        ? '<h1>M\u0259xfilik siyas\u0259ti</h1><p>Oyun Google v\u0259 Facebook il\u0259 giri\u015fd\u0259 yaln\u0131z ad\u0131n\u0131z\u0131 v\u0259 e-po\u00e7t \u00fcnvan\u0131n\u0131z\u0131 al\u0131r. Bu m\u0259lumat yaln\u0131z oyun hesab\u0131n\u0131z\u0131 bu giri\u015fl\u0259 ba\u011flamaq v\u0259 yed\u0259yi bərpa etm\u0259k \u00fc\u00e7\u00fcn istifad\u0259 olunur. M\u0259lumat \u00fc\u00e7\u00fcnc\u00fc t\u0259r\u0259fl\u0259rl\u0259 payla\u015f\u0131lm\u0131r v\u0259 satılmır.</p><p>Hesab\u0131n\u0131z\u0131n silinm\u0259sini ist\u0259s\u0259niz, e-po\u00e7t il\u0259 m\u00fcraci\u0259t edin.</p><p><a href="/">Ana s\u0259hif\u0259</a></p>'
        : '<h1>Oyun</h1><p>Bu, oyunun giri\u015f v\u0259 hesab yed\u0259yi serveridir.</p><p><a href="/privacy">M\u0259xfilik siyas\u0259ti</a></p>'));
    }
    json(rs, 404, { error: 'not found' });
  } catch (e) { rs.writeHead(500); rs.end('Server xətası'); }
}).listen(PORT, () => console.log('Auth server:', BASE));
