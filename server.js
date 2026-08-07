/*
 * 丛录 · 百度网盘同步后端（零依赖，仅需 Node 18+）
 * 功能：
 *   1) 托管 recorder.html（同一端口，麦克风在 localhost 下可用）
 *   2) 百度网盘开放平台 OAuth2 授权码流程（换取 access_token + refresh_token）
 *   3) 通过 XPan API 三步法（precreate -> upload -> create）上传音频 + markdown 纪要
 *      到 /apps/<应用名>/丛录/ 目录
 *
 * 运行： node server.js        （默认端口 8000）
 * 可选环境变量：
 *   PORT        监听端口，默认 8000
 *   PUBLIC_URL  若用 https 隧道/自有域名访问，请设为对外可达的基地址，例如
 *               https://xxx.example.com  （用于拼接 OAuth 回调地址，必须与百度后台登记一致）
 *   ACCESS_PASS 若设置，则所有访客需先输入此口令才能进入 / 保存（软门槛，非登录）。
 *               验证通过后下发有效期 30 天的令牌缓存在访客本机，过期才需重输。
 *               留空则任何人可免验证使用。
 *   GATE_SECRET 访问令牌签名密钥；不设则默认由 ACCESS_PASS 派生（重启仍有效）。
 *
 * 凭据与令牌保存在同目录的 baidu_token.json，仅存于你本机，请勿外传。
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 8000;
const PUBLIC_URL = (process.env.PUBLIC_URL || '').replace(/\/$/, '');
const TOKEN_FILE = path.join(__dirname, 'baidu_token.json');
const HTML_FILE = path.join(__dirname, 'recorder.html');
const BLOCK = 4 * 1024 * 1024; // 百度 XPan 分片大小 4MB

let tokens = loadTokens();
// 允许用环境变量预置凭据（便于云主机/无持久盘环境部署，重启后可自愈）：
//   BAIDU_AK / BAIDU_SK / BAIDU_APP / BAIDU_REFRESH_TOKEN
if (process.env.BAIDU_AK) tokens.ak = process.env.BAIDU_AK;
if (process.env.BAIDU_SK) tokens.sk = process.env.BAIDU_SK;
if (process.env.BAIDU_APP) tokens.appName = process.env.BAIDU_APP;
if (process.env.BAIDU_REFRESH_TOKEN) tokens.refresh_token = process.env.BAIDU_REFRESH_TOKEN;
const oauthStates = new Map(); // state -> { ts, redirect }

/* ---------------- 访问口令（软门槛，非登录） ---------------- */
// 设置环境变量 ACCESS_PASS 即开启访问口令；留空则任何人可免验证使用。
// 口令验证通过后下发一个有效期 30 天的签名令牌，前端缓存，过期才需重输。
const ACCESS_PASS = (process.env.ACCESS_PASS || '').trim();
// GATE_SECRET 默认由口令派生，重启后令牌仍有效；如需更稳可显式设置环境变量 GATE_SECRET。
const GATE_SECRET = process.env.GATE_SECRET || (ACCESS_PASS ? crypto.createHash('sha256').update('gate:' + ACCESS_PASS).digest('hex') : '');
const GATE_TTL = 30 * 24 * 60 * 60 * 1000; // 30 天

function signGate(exp) {
  const payload = Buffer.from(JSON.stringify({ exp })).toString('base64url');
  const sig = crypto.createHmac('sha256', GATE_SECRET).update(payload).digest('base64url');
  return payload + '.' + sig;
}
function verifyGate(token) {
  if (!token || !GATE_SECRET) return false;
  const [payload, sig] = String(token).split('.');
  if (!payload || !sig) return false;
  const expected = crypto.createHmac('sha256', GATE_SECRET).update(payload).digest('base64url');
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return false;
  try { const obj = JSON.parse(Buffer.from(payload, 'base64url').toString()); return obj.exp > Date.now(); }
  catch { return false; }
}

/* ---------------- 持久化 ---------------- */
function loadTokens() {
  try { return JSON.parse(fs.readFileSync(TOKEN_FILE, 'utf8')); }
  catch { return {}; }
}
function saveTokens() {
  try { fs.writeFileSync(TOKEN_FILE, JSON.stringify(tokens, null, 2)); }
  catch (e) { console.error('保存令牌失败:', e.message); }
}

/* ---------------- 工具 ---------------- */
function nowMs() { return Date.now(); }
function sendJSON(res, code, obj) {
  res.writeHead(code, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
function serveHTML(res) {
  fs.readFile(HTML_FILE, (err, buf) => {
    if (err) { res.writeHead(500); res.end('recorder.html 未找到'); return; }
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(buf);
  });
}
function serveCallbackHtml(res, msg, ok) {
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end(`<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><title>百度网盘授权</title>
<style>body{font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;display:grid;place-items:center;height:100vh;margin:0;background:#f5f6fb;color:#1f2430}
div{text-align:center;background:#fff;padding:34px 44px;border-radius:18px;box-shadow:0 8px 30px rgba(40,50,90,.08);max-width:360px}
h2{margin:0 0 10px;font-size:20px}.ok{color:#1fb877}.bad{color:#ff4d5e}
p{color:#3a4154;line-height:1.6;margin:6px 0}.sub{color:#8a90a2;font-size:12px}
button{margin-top:18px;border:0;background:#5b6cff;color:#fff;padding:11px 20px;border-radius:11px;cursor:pointer;font-size:14px;font-weight:600}</style></head>
<body><div><h2 class="${ok ? 'ok' : 'bad'}">${ok ? '✓ 授权成功' : '授权未完成'}</h2>
<p>${msg}</p><button onclick="window.close()">关闭窗口</button>
<p class="sub">可手动关闭此窗口，返回应用即可。</p></div></body></html>`);
}

/* ---------------- 百度令牌管理 ---------------- */
async function refreshToken() {
  if (!tokens.refresh_token || !tokens.ak || !tokens.sk) throw new Error('缺少刷新所需参数');
  const r = await fetch('https://openapi.baidu.com/oauth/2.0/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: tokens.refresh_token,
      client_id: tokens.ak,
      client_secret: tokens.sk
    })
  });
  const j = await r.json();
  if (j.access_token) {
    tokens.access_token = j.access_token;
    tokens.expires_at = nowMs() + (j.expires_in || 2592000) * 1000;
    if (j.refresh_token) tokens.refresh_token = j.refresh_token;
    saveTokens();
  } else {
    throw new Error(j.error_description || j.error || 'refresh 失败');
  }
}
// 确保有可用令牌；临近过期则自动刷新
async function ensureToken() {
  if (!tokens.access_token) return { ok: false, error: '未授权，请先完成百度网盘授权' };
  if (tokens.expires_at && tokens.expires_at - nowMs() < 5 * 60 * 1000) {
    if (tokens.refresh_token) {
      try { await refreshToken(); }
      catch (e) { return { ok: false, error: '令牌刷新失败：' + e.message }; }
    } else {
      return { ok: false, error: '令牌已过期且无刷新令牌，请重新授权' };
    }
  }
  return { ok: true };
}

/* ---------------- 百度 XPan 上传 ---------------- */
async function baiduPost(method, params) {
  const url = `https://pan.baidu.com/rest/2.0/xpan/file?method=${method}&access_token=${encodeURIComponent(tokens.access_token)}`;
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', 'User-Agent': 'pan.baidu.com' },
    body: new URLSearchParams(params).toString()
  });
  const text = await r.text();
  try { return JSON.parse(text); }
  catch { return { errno: -1, raw: text }; }
}
async function md5Hex(buf) { return crypto.createHash('md5').update(buf).digest('hex'); }

/* 确保远程目录存在（递归创建） */
async function ensureDir(remoteDir) {
  // 百度 XPan 的 create 接口：isdir=1 创建目录
  const parts = remoteDir.split('/').filter(Boolean);
  let cur = '';
  // /apps 与 /apps/<应用名> 是百度系统保留根目录，授权时已自动创建，应用无权/无需创建，
  // 从应用专属子目录开始创建即可，避免 errno=102（对保留目录创建失败）导致整体失败。
  const startIdx = (parts[0] === 'apps') ? 2 : 0;
  for (let i = startIdx; i < parts.length; i++) {
    cur += '/' + parts[i];
    try {
      const r = await baiduPost('create', { path: cur, isdir: '1', size: '0' });
      // 0 成功；-8 / 31029 / 102 均表示已存在或保留目录，忽略继续
      if (r.errno !== 0 && r.errno !== -8 && r.errno !== 31029 && r.errno !== 102) {
        throw new Error(`创建目录 ${cur} 失败 errno=${r.errno} ${r.errmsg || ''}`);
      }
    } catch (e) {
      if (!/-(8|102)|31029|已存在/.test(e.message)) throw e;
    }
  }
}

async function uploadFile(remotePath, buffer) {
  // 1) 分片 + 计算每片 md5
  const parts = [];
  const blockList = [];
  for (let i = 0; i < buffer.length; i += BLOCK) {
    const chunk = buffer.subarray(i, i + BLOCK);
    parts.push(chunk);
    blockList.push(await md5Hex(chunk));
  }
  // 2) precreate
  const pre = await baiduPost('precreate', {
    path: remotePath,
    size: String(buffer.length),
    isdir: '0',
    autoinit: '1',
    rtype: '1',
    block_list: JSON.stringify(blockList)
  });
  if (pre.errno !== 0 && pre.errno !== -8) {
    throw new Error('precreate 失败 errno=' + pre.errno + (pre.errmsg ? ' ' + pre.errmsg : ''));
  }
  console.log('[baidu] precreate ->', JSON.stringify(pre));
  const uploadid = pre.uploadid;
  if (!uploadid) throw new Error('precreate 未返回 uploadid');
  // 3) 逐片上传（raw binary：百度 XPan 最稳妥的方式，避免 multipart 在 Node fetch 下落盘失败）
  for (let i = 0; i < parts.length; i++) {
    const upUrl = `https://pan.baidu.com/rest/2.0/xpan/file?method=upload`
      + `&access_token=${encodeURIComponent(tokens.access_token)}`
      + `&path=${encodeURIComponent(remotePath)}`
      + `&uploadid=${encodeURIComponent(uploadid)}`
      + `&partseq=${i}`
      + `&type=0`;
    const r = await fetch(upUrl, {
      method: 'POST',
      headers: { 'User-Agent': 'pan.baidu.com', 'Content-Type': 'application/octet-stream' },
      body: parts[i]
    });
    const j = await r.json().catch(() => ({}));
    console.log(`[baidu] upload 分片${i} ->`, JSON.stringify(j));
    if (j.errno !== 0 && j.errno !== undefined) {
      throw new Error('upload 分片 ' + i + ' 失败 errno=' + j.errno + (j.errmsg ? ' ' + j.errmsg : ''));
    }
  }
  // 4) create 合并
  const cre = await baiduPost('create', {
    path: remotePath,
    size: String(buffer.length),
    isdir: '0',
    block_list: JSON.stringify(blockList),
    uploadid,
    rtype: '1'
  });
  console.log('[baidu] create ->', JSON.stringify(cre));
  if (cre.errno !== 0 && cre.errno !== undefined) {
    throw new Error('create 失败 errno=' + cre.errno + (cre.errmsg ? ' ' + cre.errmsg : ''));
  }
  return cre;
}

function buildNote(meta) {
  const d = new Date(meta.createdAt || Date.now());
  const p = n => String(n).padStart(2, '0');
  const fmt = `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
  const mm = Math.floor((meta.duration || 0) / 60), ss = Math.floor((meta.duration || 0) % 60);
  const dur = `${String(mm).padStart(2, '0')}:${String(ss).padStart(2, '0')}`;
  return `# ${meta.title || '丛录'}\n\n` +
    `- 时间：${fmt}\n` +
    `- 说话人：${meta.speaker || '未指定'}\n` +
    `- 地点：${meta.locationName || '未记录'}\n` +
    `- 时长：${dur}\n\n` +
    `## 转写文字\n\n${meta.transcript || '（无文字记录）'}\n`;
}
function fileTs(ts) {
  const d = new Date(ts || Date.now());
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}_${p(d.getHours())}-${p(d.getMinutes())}-${p(d.getSeconds())}`;
}
function safeName(s) { return (s || 'record').replace(/[\\/:*?"<>|]/g, '_').slice(0, 60); }

/* ---------------- 请求路由 ---------------- */
const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://localhost');
  const p = u.pathname;

  try {
    if (p === '/' || p === '/recorder.html') { serveHTML(res); return; }
    if (p === '/healthz') { res.writeHead(200); res.end('ok'); return; }

    // 访问口令：是否开启 + 校验
    if (p === '/api/gate/status') {
      return sendJSON(res, 200, { enabled: !!ACCESS_PASS });
    }
    if (p === '/api/gate/verify' && req.method === 'POST') {
      if (!ACCESS_PASS) return sendJSON(res, 200, { ok: true, token: '' });
      const buf = await readBody(req);
      let body; try { body = JSON.parse(buf.toString('utf8')); } catch { return sendJSON(res, 400, { ok: false, error: '参数错误' }); }
      if ((body.pass || '').trim() === ACCESS_PASS) {
        return sendJSON(res, 200, { ok: true, token: signGate(Date.now() + GATE_TTL) });
      }
      return sendJSON(res, 401, { ok: false, error: '口令不正确' });
    }

    // 配置 AK/SK/应用名
    if (p === '/api/baidu/config' && req.method === 'POST') {
      const buf = await readBody(req);
      let body; try { body = JSON.parse(buf.toString('utf8')); } catch { return sendJSON(res, 400, { ok: false, error: '参数错误' }); }
      tokens.ak = (body.ak || '').trim();
      tokens.sk = (body.sk || '').trim();
      tokens.appName = (body.appName || '').trim();
      saveTokens();
      return sendJSON(res, 200, { ok: true });
    }

    // 状态查询
    if (p === '/api/baidu/status') {
      return sendJSON(res, 200, {
        ok: true,
        configured: !!(tokens.ak && tokens.sk),
        authorized: !!(tokens.access_token && (!tokens.expires_at || tokens.expires_at > nowMs())),
        expires_at: tokens.expires_at || 0,
        appName: tokens.appName || '',
        akMasked: tokens.ak ? tokens.ak.slice(0, 4) + '****' : ''
      });
    }

    // 返回 refresh_token（仅已授权时），用于固化到环境变量，重启不丢
    if (p === '/api/baidu/token-info' && req.method === 'GET') {
      if (!tokens.refresh_token) return sendJSON(res, 400, { ok: false, error: '尚未授权，无可复制的 refresh_token' });
      return sendJSON(res, 200, { ok: true, refresh_token: tokens.refresh_token });
    }

    // 生成授权链接
    if (p === '/api/baidu/auth-url') {
      if (!tokens.ak || !tokens.sk) return sendJSON(res, 400, { ok: false, error: '请先在上方填写 API Key / Secret Key 并保存配置' });
      const state = crypto.randomBytes(8).toString('hex');
      const base = PUBLIC_URL || ('http://' + (req.headers.host || 'localhost:8000'));
      const redirect = base + '/oauth/baidu/callback';
      oauthStates.set(state, { ts: nowMs(), redirect });
      const authUrl = 'https://openapi.baidu.com/oauth/2.0/authorize?' + new URLSearchParams({
        response_type: 'code',
        client_id: tokens.ak,
        redirect_uri: redirect,
        scope: 'basic,netdisk',
        state,
        display: 'popup'
      }).toString();
      return sendJSON(res, 200, { ok: true, url: authUrl });
    }

    // OAuth 回调：用 code 换 token
    if (p === '/oauth/baidu/callback') {
      const err = u.searchParams.get('error');
      const code = u.searchParams.get('code');
      const state = u.searchParams.get('state');
      if (err) return serveCallbackHtml(res, '授权被拒绝：' + err, false);
      const st = oauthStates.get(state);
      if (!code || !state || !st) return serveCallbackHtml(res, '授权回调参数无效或已过期，请重新点击「前往授权」', false);
      oauthStates.delete(state);
      try {
        const r = await fetch('https://openapi.baidu.com/oauth/2.0/token', {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            client_id: tokens.ak,
            client_secret: tokens.sk,
            redirect_uri: st.redirect
          })
        });
        const j = await r.json();
        if (j.access_token) {
          tokens.access_token = j.access_token;
          tokens.expires_at = nowMs() + (j.expires_in || 2592000) * 1000;
          if (j.refresh_token) tokens.refresh_token = j.refresh_token;
          saveTokens();
          return serveCallbackHtml(res, '已成功连接你的百度网盘，返回应用即可。', true);
        }
        return serveCallbackHtml(res, '换取令牌失败：' + (j.error_description || j.error || '未知错误'), false);
      } catch (e) {
        return serveCallbackHtml(res, '换取令牌出错：' + e.message, false);
      }
    }

    // 保存：上传音频 + markdown 到网盘
    if (p === '/api/save' && req.method === 'POST') {
      if (ACCESS_PASS && !verifyGate(req.headers['x-gate-token'])) {
        return sendJSON(res, 401, { ok: false, error: 'ACCESS_DENIED' });
      }
      const t = await ensureToken();
      if (!t.ok) return sendJSON(res, 401, { ok: false, error: t.error });
      if (!tokens.appName) return sendJSON(res, 400, { ok: false, error: '未配置应用目录名(appName)，请在同步设置中填写' });
      const buf = await readBody(req);
      let body; try { body = JSON.parse(buf.toString('utf8')); } catch { return sendJSON(res, 400, { ok: false, error: '参数错误' }); }
      const meta = body.meta || {};
      const audio = body.audio || {};
      let audioBuf;
      try { audioBuf = Buffer.from((audio.data || '').split(',')[1] || '', 'base64'); }
      catch { return sendJSON(res, 400, { ok: false, error: '音频数据解析失败' }); }
      if (!audioBuf.length) return sendJSON(res, 400, { ok: false, error: '音频为空' });

      const base = `${safeName(meta.title)}_${fileTs(meta.createdAt)}`;
      // 网盘音频统一存为 .mp3（满足「网盘只存 mp3」要求；内容与删除端一致，确保删除能精准匹配）
      const audioName = base + '.mp3';
      const noteName = base + '.md';
      const dir = `/apps/${tokens.appName}/丛录`;
      const audioPath = `${dir}/${audioName}`;
      const notePath = `${dir}/${noteName}`;
      console.log(`[baidu] /api/save 开始：audio=${audioPath} size=${audioBuf.length}B dir=${dir}`);
      try {
        await ensureDir(dir);  // 先创建 /apps/<应用名>/丛录 目录
        await uploadFile(audioPath, audioBuf);
        await uploadFile(notePath, Buffer.from(buildNote(meta), 'utf8'));
        console.log('[baidu] /api/save 完成：', audioPath, notePath);
        return sendJSON(res, 200, { ok: true, audioPath, notePath });
      } catch (e) {
        console.error('[baidu] /api/save 失败：', e.message);
        return sendJSON(res, 500, { ok: false, error: e.message });
      }
    }

    // 删除：同步删除百度网盘上的音频 + 纪要文件
    if (p === '/api/delete' && req.method === 'POST') {
      if (ACCESS_PASS && !verifyGate(req.headers['x-gate-token'])) {
        return sendJSON(res, 401, { ok: false, error: 'ACCESS_DENIED' });
      }
      const t = await ensureToken();
      if (!t.ok) return sendJSON(res, 401, { ok: false, error: t.error });
      if (!tokens.appName) return sendJSON(res, 400, { ok: false, error: '未配置应用目录名(appName)' });
      const buf = await readBody(req);
      let body; try { body = JSON.parse(buf.toString('utf8')); } catch { return sendJSON(res, 400, { ok: false, error: '参数错误' }); }
      const title = body.title || '';
      const createdAt = body.createdAt;
      if (!createdAt) return sendJSON(res, 400, { ok: false, error: '缺少 createdAt' });
      const base = `${safeName(title)}_${fileTs(createdAt)}`;
      const dir = `/apps/${tokens.appName}/丛录`;
      const paths = [`${dir}/${base}.mp3`, `${dir}/${base}.md`];
      console.log('[baidu] /api/delete 开始：', paths);
      try {
        const delUrl = `https://pan.baidu.com/rest/2.0/xpan/file?method=filemanager&opera=delete&access_token=${encodeURIComponent(tokens.access_token)}`;
        const r = await fetch(delUrl, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded', 'User-Agent': 'pan.baidu.com' },
          body: new URLSearchParams({ filelist: JSON.stringify(paths), async: '0' }).toString()
        });
        const j = await r.json().catch(() => ({}));
        console.log('[baidu] /api/delete 结果：', JSON.stringify(j));
        if (j.errno === 0) return sendJSON(res, 200, { ok: true, paths });
        // 文件不存在(-7/-9 等)也视为已删除，不阻塞本地删除
        if (j.errno === -7 || j.errno === -9) return sendJSON(res, 200, { ok: true, paths, skipped: '文件不存在' });
        return sendJSON(res, 500, { ok: false, error: (j.errmsg || '删除失败 errno=' + j.errno) });
      } catch (e) {
        console.error('[baidu] /api/delete 失败：', e.message);
        return sendJSON(res, 500, { ok: false, error: e.message });
      }
    }

    sendJSON(res, 404, { ok: false, error: 'not found' });
  } catch (e) {
    sendJSON(res, 500, { ok: false, error: e.message });
  }
});

server.listen(PORT, () => {
  const shown = PUBLIC_URL || ('http://localhost:' + PORT);
  console.log('丛录服务已启动：' + shown);
  console.log('百度网盘令牌文件：' + TOKEN_FILE);
});
