'use strict';

const MODDIR = '/data/adb/modules/sandboxid';
const ROTATE_SH = `${MODDIR}/rotate_ids.sh`;
const IDENTITY = `${MODDIR}/identity.prop`;
const TARGETS = `${MODDIR}/target.txt`;
const CARRIERS = `${MODDIR}/carriers.tsv`;
const CARRIER_CONF = `${MODDIR}/carrier.conf`;
const SELFTEST_SH = `${MODDIR}/selftest.sh`;

const ROTATE_LOG = `${MODDIR}/debug/rotate.log`;
const ACTION_LOG = `${MODDIR}/debug/action.log`;

function shq(s) { return "'" + String(s).replace(/'/g, "'\\''") + "'"; }

const ENV = `cd ${shq(MODDIR)} && export MODDIR=${shq(MODDIR)} && export PATH=${shq(MODDIR + '/bin')}:\"$PATH\"`;

const BRAND_DOT = {
  google: '#4285f4', samsung: '#2e6be6', xiaomi: '#ff6900', redmi: '#ff453a',
  poco: '#ffcc00', oppo: '#10b981', vivo: '#3aa0ff', infinix: '#00c2a8',
};
function setBrand(brand) {
  const hex = BRAND_DOT[String(brand || '').trim().toLowerCase()] || '';
  const root = document.documentElement.style;
  if (hex) root.setProperty('--brand', hex);
  else root.removeProperty('--brand');
}

function exec(cmd, timeoutMs) {
  const limit = typeof timeoutMs === 'number' && timeoutMs > 0 ? timeoutMs : 30000;
  return new Promise((resolve, reject) => {
    if (typeof ksu === 'undefined' || !ksu.exec) {
      reject(new Error('root bridge tidak tersedia'));
      return;
    }
    const cbName = `__ksucb_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      try { delete window[cbName]; } catch (_) { window[cbName] = undefined; }
      reject(Object.assign(new Error(`timeout setelah ${limit}ms`), { code: -1, stdout: '', stderr: '' }));
    }, limit);
    window[cbName] = function (errno, stdout, stderr) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { delete window[cbName]; } catch (e) { window[cbName] = undefined; }
      const code = Number(errno);
      const out = String(stdout || '');
      const err = String(stderr || '');
      if (code === 0) {
        resolve(out);
      } else {
        const msg = (err.trim() || out.trim() || `exit ${code}`);
        reject(Object.assign(new Error(msg), { code, stdout: out, stderr: err }));
      }
    };
    try {
      ksu.exec(cmd, '{}', cbName);
    } catch (e) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { delete window[cbName]; } catch (_) {}
      reject(e);
    }
  });
}

async function shell(cmd) { return exec(cmd); }

async function run(cmd) {
  try { return { ok: true, out: await shell(cmd) }; }
  catch (e) { return { ok: false, err: e }; }
}

const ICON = { ok: '\u2713', error: '\u2715', warn: '\u26a0', info: '\u2139' };
const T = {};

function toastInit() {
  T.el = document.getElementById('toast');
  T.icon = document.getElementById('toastIcon');
  T.title = document.getElementById('toastTitle');
  T.exp = document.getElementById('toastExp');
  T.detail = document.getElementById('toastDetail');
  document.getElementById('toastClose').addEventListener('click', hideToast);
  T.exp.addEventListener('click', toggleToast);
  T.title.addEventListener('click', () => { if (!T.exp.hidden) toggleToast(); });
}

function toast(title, opts) {
  opts = opts || {};
  const kind = opts.kind || 'info';
  const detail = String(opts.detail || '').trim();
  const hasDetail = detail.length > 0;
  T.icon.textContent = ICON[kind] || ICON.info;
  T.title.textContent = title || '';
  T.el.className = 'toast show ' + kind;
  T.exp.hidden = !hasDetail;
  T.detail.hidden = true;
  T.detail.innerHTML = hasDetail ? renderLogHtml(detail) : '';
  T.title.style.cursor = hasDetail ? 'pointer' : 'default';
  clearTimeout(toast._t);
  const sticky = opts.sticky || kind === 'error';
  if (!sticky) toast._t = setTimeout(hideToast, kind === 'warn' ? 4200 : 2600);
}

function toggleToast() {
  const open = T.el.classList.toggle('open');
  T.detail.hidden = !open;
  if (open) clearTimeout(toast._t);
}

function hideToast() {
  clearTimeout(toast._t);
  T.el.className = 'toast';
  T.detail.hidden = true;
}

function trimTitle(s) {
  const first = String(s || '').split('\n').map(x => x.trim()).filter(Boolean)[0] || 'Error';
  return first.length > 90 ? first.slice(0, 89) + '\u2026' : first;
}

async function safeExec(cmd, okMsg) {
  try {
    const out = await shell(cmd);
    if (okMsg) toast(okMsg, { kind: 'ok' });
    return { ok: true, out };
  } catch (e) {
    toast(trimTitle(e.message || String(e)), { kind: 'error', detail: e.stdout || e.stderr || '' });
    return { ok: false, err: e };
  }
}

async function withLoading(btn, fn) {
  if (!btn || btn.dataset.busy) return;
  btn.dataset.busy = '1';
  btn.classList.add('loading');
  btn.disabled = true;
  btn.setAttribute('aria-busy', 'true');
  try { return await fn(); }
  finally {
    btn.disabled = false;
    btn.classList.remove('loading');
    btn.removeAttribute('aria-busy');
    delete btn.dataset.busy;
  }
}

function classifyLine(raw) {
  let ts = '';
  let rest = raw;
  const m = raw.match(/^(\[\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d\])\s?(.*)$/);
  if (m) { ts = m[1]; rest = m[2]; }
  let lvl = 'info';
  if (/^==>/.test(rest)) lvl = 'step';
  else if (/^\[OK\]/.test(rest) || /^OK\b/.test(rest)) lvl = 'ok';
  else if (/^\[WARN\]/.test(rest)) lvl = 'warn';
  else if (/^\[ERR\]/.test(rest) || /^!/.test(rest)) lvl = 'err';
  else {
    const lc = rest.match(/^\d\d-\d\d \d\d:\d\d:\d\d\.\d+\s+([VDIWEF])\//);
    const p = lc ? lc[1] : '';
    if (p === 'E' || p === 'F') lvl = 'err';
    else if (p === 'W') lvl = 'warn';
    else if (p === 'V' || p === 'D') lvl = 'info';
  }
  return { ts, rest, lvl };
}

function renderLogHtml(text) {
  return String(text).replace(/\r/g, '').split('\n').map(line => {
    if (line === '') return '<div class="ln">&nbsp;</div>';
    const c = classifyLine(line);
    const ts = c.ts ? `<span class="ts">${escapeHtml(c.ts)}</span> ` : '';
    return `<div class="ln lvl-${c.lvl}">${ts}${escapeHtml(c.rest)}</div>`;
  }).join('');
}

function summarizeAction(out) {
  const text = String(out || '');
  if (/^OK - persona baru aktif/m.test(text)) {
    const b = (text.match(/^\s*BRAND\s*:\s*(.+)$/m) || [])[1];
    const md = (text.match(/^\s*MODEL\s*:\s*(.+)$/m) || [])[1];
    const label = [b && b.trim(), md && md.trim()].filter(Boolean).join(' \u00b7 ');
    return { kind: 'ok', title: label ? `Perangkat baru \u00b7 ${label}` : 'Perangkat baru aktif', detail: text };
  }
  if (/^OK - fresh/m.test(text)) {
    const md = (text.match(/^\s*MODEL\s*:\s*(.+)$/m) || [])[1];
    return { kind: 'ok', title: md ? `Perangkat baru \u00b7 ${md.trim()}` : 'Perangkat baru siap', detail: text };
  }
  const bang = (text.match(/^(?:Gagal\b|[\u2717!]).*$/m) || [])[0];
  return { kind: 'error', title: trimTitle(bang || text || 'Gagal mengacak perangkat'), detail: text };
}

function summarizeRotate(out, label) {
  const text = String(out || '');
  const errs = (text.match(/\[ERR\]/g) || []).length;
  const warns = (text.match(/\[WARN\]/g) || []).length;
  const fail = text.match(/(\d+) step\(s\) reported failure/);
  const reboot = /REBOOT REQUIRED/i.test(text);
  const name = label || 'Rotasi';
  if (errs > 0 || (fail && Number(fail[1]) > 0)) {
    const n = fail ? fail[1] : String(errs);
    return { kind: 'error', title: `${name}: ${n} langkah gagal`, detail: text };
  }
  let note = '';
  let kind = 'ok';
  if (reboot) { note = ' \u00b7 perlu reboot'; kind = 'warn'; }
  else if (warns > 0) { note = ` \u00b7 ${warns} warning`; kind = 'warn'; }
  return { kind, title: `${name} selesai${note}`, detail: text };
}

function wireTabs() {
  document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(b => b.classList.toggle('active', b === btn));
      const id = btn.dataset.tab;
      document.querySelectorAll('.page').forEach(p => p.classList.toggle('active', p.id === id));
      moveIndicator();
      onTab(id);
    });
  });
}

function moveIndicator() {
  const nav = document.getElementById('nav');
  const ind = document.getElementById('navInd');
  const btn = nav && nav.querySelector('.tab.active');
  if (!nav || !ind || !btn) return;
  ind.style.width = btn.offsetWidth + 'px';
  ind.style.transform = `translateX(${btn.offsetLeft - nav.scrollLeft}px)`;
}

function onTab(id) {
  if (id === 'persona') loadPersona();
  else if (id === 'rotate') loadRotate();
  else if (id === 'sim') loadSim();
  else if (id === 'targets') loadTargets();
  else if (id === 'selftest') loadSelftest();
  else if (id === 'log') loadLog();
}

function parseProp(text) {
  const out = {};
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const eq = t.indexOf('=');
    if (eq <= 0) continue;
    out[t.slice(0, eq).trim()] = t.slice(eq + 1).trim();
  }
  return out;
}

function skLines(n) {
  let s = '';
  for (let i = 0; i < n; i++) s += `<div class="ln sk sk-line${i % 3 === 2 ? ' short' : ''}"></div>`;
  return s;
}

function skKv(n) {
  let s = '';
  for (let i = 0; i < n; i++) s += '<div class="k sk sk-line short"></div><div class="v sk sk-line"></div>';
  return s;
}

const DETAIL_KEYS = [
  ['MANUFACTURER', 'Pabrikan'], ['PRODUCT', 'Product'], ['BOARD', 'Board'],
  ['SOC_MANUFACTURER', 'SoC vendor'], ['SOC_MODEL', 'SoC'],
  ['SECURITY_PATCH', 'Security patch'],
  ['SERIAL', 'Serial'], ['ANDROID_ID', 'Android ID'], ['GOOGLE_AID', 'Google AID'],
  ['WIFI_MAC', 'WiFi MAC'], ['BLUETOOTH_ADDR', 'BT MAC'], ['BLUETOOTH_NAME', 'Nama BT'],
  ['RADIO', 'Radio'], ['FIRST_BOOT', 'Boot awal'], ['LAST_BOOT', 'Boot terakhir'],
];

function renderHero(kv) {
  const brand = kv.BRAND || '';
  const mkt = kv.MARKETNAME || kv.MODEL || '(tidak dikenal)';
  const sub = [kv.MODEL, kv.DEVICE].filter(Boolean).join(' \u00b7 ');
  const rel = kv.RELEASE || '', sdk = kv.SDK_INT || '';
  const os = rel
    ? `Android ${escapeHtml(rel)}${sdk ? ` \u00b7 SDK ${escapeHtml(sdk)}` : ''}`
    : '';
  return `${brand ? `<span class="brandchip">${escapeHtml(brand)}</span>` : ''}` +
    `<div class="mkt">${escapeHtml(mkt)}</div>` +
    `${sub ? `<div class="mdl">${escapeHtml(sub)}</div>` : ''}` +
    `${os ? `<div class="os">${os}</div>` : ''}` +
    `${kv.FINGERPRINT ? `<div class="fp">${escapeHtml(kv.FINGERPRINT)}</div>` : ''}`;
}

function renderTiles(kv) {
  const t = [];
  if (kv.BOOT_COUNT)
    t.push(`<div class="tile boot"><div class="tlabel">Boot count</div><div class="tval">${escapeHtml(kv.BOOT_COUNT)}</div><div class="tsub">jumlah reboot</div></div>`);
  const up = kv.UPTIME_HUMAN || (kv.UPTIME_SECONDS ? kv.UPTIME_SECONDS + 's' : '');
  if (up)
    t.push(`<div class="tile up"><div class="tlabel">Uptime</div><div class="tval">${escapeHtml(up)}</div><div class="tsub">lama menyala</div></div>`);
  if (kv.FRESH) {
    const yes = /^(y|yes|true|1)$/i.test(kv.FRESH.trim());
    t.push(`<div class="tile fresh"><div class="tlabel">Fresh</div><div class="tval ${yes ? 'yes' : 'no'}">${yes ? 'Ya' : 'Tidak'}</div><div class="tsub">baru direset?</div></div>`);
  }
  if (kv.USAGE_PROFILE)
    t.push(`<div class="tile usage"><div class="tlabel">Pemakaian</div><div class="tval">${escapeHtml(kv.USAGE_PROFILE)}</div><div class="tsub">pola pakai</div></div>`);
  return t.join('');
}

async function loadPersona() {
  const hero = document.getElementById('hero');
  const tiles = document.getElementById('tiles');
  const el = document.getElementById('identity');
  hero.innerHTML = '';
  tiles.innerHTML = '';
  el.className = 'kv';
  el.innerHTML = skKv(6);
  const r = await safeExec(`cat ${shq(IDENTITY)} 2>/dev/null || true`);
  if (!r.ok || !r.out.trim()) {
    setBrand('');
    hero.innerHTML = '<div class="empty">Belum ada perangkat. Tekan "Acak perangkat baru" untuk mulai.</div>';
    el.className = 'kv';
    el.innerHTML = '<div class="empty">identity.prop belum ada.</div>';
    return;
  }
  const kv = parseProp(r.out);
  setBrand(kv.BRAND);
  hero.innerHTML = renderHero(kv);
  tiles.innerHTML = renderTiles(kv);
  tiles.querySelectorAll('.tile').forEach((elt, i) => elt.style.setProperty('--i', i));
  const html = DETAIL_KEYS.map(([k, label]) => {
    const v = kv[k];
    if (v === undefined || v === '') return '';
    return `<div class="k">${escapeHtml(label)}</div><div class="v">${escapeHtml(v)}</div>`;
  }).join('');
  el.className = 'kv in';
  el.innerHTML = html || '<div class="empty">identity.prop kosong.</div>';
}

document.getElementById('refreshBtn').addEventListener('click', loadPersona);
document.getElementById('freshenBtn').addEventListener('click', (ev) => withLoading(ev.currentTarget, async () => {
  const cmd = `${ENV} && sh ${shq(MODDIR)}/action.sh 2>&1`;
  const r = await run(cmd);
  if (!r.ok) toast(trimTitle(r.err.message || 'Gagal mengacak perangkat'), { kind: 'error', detail: r.err.stdout || r.err.stderr || '' });
  else { const s = summarizeAction(r.out); toast(s.title, { kind: s.kind, detail: s.detail }); }
  loadPersona();
  if (document.getElementById('rotate').classList.contains('active')) loadRotate();
}));

const ROT_CARDS = [
  { key: 'ssaid',       name: 'SSAID',         desc: 'Android ID per-aplikasi (Settings.Secure) — dihapus, dibuat ulang setelah reboot', get: 'ANDROID_ID' },
  { key: 'gaid',        name: 'Google AID',    desc: 'Advertising ID (Settings.Global + XML GMS)',        get: 'GOOGLE_AID' },
  { key: 'wlan-mac',    name: 'WiFi MAC',      desc: 'MAC wlan0 + reset WifiConfigStore',                 get: 'WIFI_MAC' },
  { key: 'bt-mac',      name: 'Bluetooth MAC', desc: 'MAC adapter BT + Address di bt_config.conf',        get: 'BLUETOOTH_ADDR' },
  { key: 'device-name', name: 'Nama perangkat', desc: 'device_name = MODEL dari identity.prop',           get: 'MODEL' },
  { key: 'boot-count',  name: 'Boot count',    desc: 'Settings.Global.boot_count = BOOT_COUNT identity.prop', get: 'BOOT_COUNT' },
  { key: 'applog',      name: 'AppLog ByteDance', desc: 'did/iid/ssid/openudid/clientudid/cdid untuk TikTok/Douyin — di-spoof in-process oleh hook JNI (L9)', get: null, applog: true },
];

async function loadRotate() {
  const wrap = document.getElementById('rotCards');
  wrap.innerHTML = ROT_CARDS.map((c, i) => `
    <div class="card" data-key="${c.key}">
      <div class="name">${c.name}</div>
      <div class="desc">${c.desc}</div>
      <div class="val sk sk-line" data-slot="val"></div>
      <div class="actions"><button class="sm" data-rot="${c.key}">Rotasi</button></div>
    </div>`).join('');
  wrap.querySelectorAll('.card').forEach((el, i) => el.style.setProperty('--i', i));
  wrap.querySelectorAll('button[data-rot]').forEach(b => {
    b.addEventListener('click', () => rotateOne(b.dataset.rot, b));
  });
  const r = await run(`cat ${shq(IDENTITY)} 2>/dev/null || true`);
  const kv = r.ok ? parseProp(r.out) : {};
  for (const c of ROT_CARDS) {
    const slot = wrap.querySelector(`.card[data-key="${c.key}"] [data-slot="val"]`);
    if (!slot) continue;
    slot.classList.remove('sk', 'sk-line');
    if (c.applog) {
      slot.textContent = '\u2026';
    } else {
      slot.textContent = (c.get && kv[c.get]) ? kv[c.get] : '\u2014';
    }
  }
  renderApplogStatus(wrap);
}

async function renderApplogStatus(wrap) {
  const slot = wrap.querySelector('.card[data-key="applog"] [data-slot="val"]');
  if (!slot) return;
  const cmd = `${ENV} && . ${shq(MODDIR + '/helpers.sh')} 2>/dev/null && ` +
    `if [ -r ${shq(TARGETS)} ]; then ` +
    `  while IFS= read -r _l || [ -n "$_l" ]; do ` +
    `    _l=$(printf '%s' "$_l" | sed -e "s/#.*//" -e "s/^[[:space:]]*//" -e "s/[[:space:]]*$//"); ` +
    `    [ -n "$_l" ] || continue; ` +
    `    applog_probe "$_l"; ` +
    `  done < ${shq(TARGETS)}; ` +
    `fi`;
  const r = await run(cmd);
  if (!r.ok) { slot.textContent = '\u2014'; return; }
  const lines = String(r.out || '').split('\n').map(x => x.trim()).filter(Boolean);
  if (lines.length === 0) {
    slot.textContent = 'target.txt kosong';
    return;
  }
  const parts = lines.map(line => {
    const [pkg, count, state] = line.split(/\s+/);
    const short = String(pkg || '').split('.').slice(-1)[0] || pkg;
    const label = { active: 'aktif', fresh: 'bersih', absent: 'nihil' }[state] || state;
    return `${short}: ${label} (${count})`;
  });
  slot.textContent = parts.join(' \u00b7 ');
  slot.title = lines.join('\n');
}

function rotateCmd(key) {
  return `${ENV} && mkdir -p ${shq(MODDIR)}/debug && ` +
    `{ printf '[%s] ==> rotate ${key} (webui)\\n' "$(date '+%F %T')"; ` +
    `sh ${shq(ROTATE_SH)} ${shq(key)} 2>&1; } | tee -a ${shq(ROTATE_LOG)}`;
}

function finishRotate(r, label) {
  if (!r.ok) toast(trimTitle(r.err.message || 'Rotasi gagal'), { kind: 'error', detail: r.err.stdout || r.err.stderr || '' });
  else { const s = summarizeRotate(r.out, label); toast(s.title, { kind: s.kind, detail: s.detail }); }
  loadRotate();
}

async function rotateOne(key, btn) {
  await withLoading(btn, async () => {
    const r = await run(rotateCmd(key));
    const label = (ROT_CARDS.find(c => c.key === key) || {}).name || key;
    finishRotate(r, label);
  });
}

document.getElementById('rotAll').addEventListener('click', (ev) => withLoading(ev.currentTarget, async () => {
  const r = await run(rotateCmd('all'));
  finishRotate(r, 'Rotasi semua');
}));

let SIM_DB = null;

function parseCarriersTsv(text) {
  const rows = [];
  for (const line of String(text).split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t[0] === '#') continue;
    const f = line.split('\t');
    if (f.length < 4) continue;
    const name = f[0].trim(), mcc = f[1].trim(), mnc = f[2].trim(), iso = f[3].trim();
    if (!name || !mcc || !mnc) continue;
    const carrierId = (f[4] || '').trim();
    rows.push({ name, mcc, mnc, iso, carrierId });
  }
  return rows;
}

function simFillCarriers(current) {
  const iso = document.getElementById('simCountry').value;
  const carSel = document.getElementById('simCarrier');
  const list = SIM_DB.filter(r => !iso || r.iso === iso)
    .sort((a, b) => a.name.localeCompare(b.name));
  carSel.innerHTML = '<option value="">Operator…</option>' +
    list.map(r => {
      const val = `${r.mcc}|${r.mnc}|${r.name}|${r.iso}`;
      return `<option value="${escapeHtml(val)}" data-cid="${escapeHtml(r.carrierId || '')}">${escapeHtml(r.name)} · ${escapeHtml(r.mcc + r.mnc)}</option>`;
    }).join('');
  if (current && current.MCC && current.MNC) {
    const want = `${current.MCC}|${current.MNC}|`;
    for (const opt of carSel.options) {
      if (opt.value.startsWith(want)) { carSel.value = opt.value; break; }
    }
  }
}

function simFill(current) {
  const cSel = document.getElementById('simCountry');
  const isos = Array.from(new Set(SIM_DB.map(r => r.iso).filter(Boolean))).sort();
  cSel.innerHTML = '<option value="">Negara…</option>' +
    isos.map(i => `<option value="${escapeHtml(i)}">${escapeHtml(i.toUpperCase())}</option>`).join('');
  const curIso = (current && current.ISO) ? current.ISO.toLowerCase() : '';
  if (curIso && isos.includes(curIso)) cSel.value = curIso;
  simFillCarriers(current);
}

function renderSimCurrent(cc) {
  const el = document.getElementById('simCurrent');
  const st = document.getElementById('simState');
  if (!cc || !cc.MCC) {
    st.textContent = 'Bawaan';
    st.className = 'chip';
    el.className = 'kv';
    el.innerHTML = '<div class="empty">Belum ada operator dipilih — pakai bawaan.</div>';
    return;
  }
  st.textContent = (cc.PHANTOM === '1') ? 'Aktif · phantom' : 'Aktif';
  st.className = 'chip chip-on';
  const rows = [
    ['Operator', cc.NAME || ''],
    ['Kode (MCC+MNC)', (cc.MCC || '') + (cc.MNC || '')],
    ['Negara', (cc.ISO || '').toUpperCase()],
    ['Carrier ID', cc.CARRIER_ID ? cc.CARRIER_ID : 'UNKNOWN (-1)'],
    ['Mode Tambah SIM', cc.PHANTOM === '1' ? 'Ya' : 'Tidak'],
  ];
  el.className = 'kv in';
  el.innerHTML = rows.map(([k, v]) => v !== ''
    ? `<div class="k">${escapeHtml(k)}</div><div class="v">${escapeHtml(v)}</div>` : '').join('');
}

async function loadSim() {
  const el = document.getElementById('simCurrent');
  el.className = 'kv';
  el.innerHTML = skKv(3);
  if (!SIM_DB || !SIM_DB.length) {
    const r = await run(`cat ${shq(CARRIERS)} 2>/dev/null || true`);
    SIM_DB = (r.ok && r.out.trim()) ? parseCarriersTsv(r.out) : [];
  }
  if (!SIM_DB.length) {
    document.getElementById('simState').textContent = '—';
    el.className = 'kv';
    el.innerHTML = '<div class="empty">carriers.tsv tidak terbaca.</div>';
    return;
  }
  const rc = await run(`cat ${shq(CARRIER_CONF)} 2>/dev/null || true`);
  const cc = (rc.ok && rc.out.trim()) ? parseProp(rc.out) : {};
  simFill(cc);
  document.getElementById('simPhantom').checked = (cc.PHANTOM === '1');
  renderSimCurrent(cc);
}

function carrierCmd(arg) {
  return `${ENV} && mkdir -p ${shq(MODDIR)}/debug && ` +
    `{ printf '[%s] ==> carrier ${arg.split('|')[0] === 'off' ? 'off' : 'set'} (webui)\\n' "$(date '+%F %T')"; ` +
    `sh ${shq(ROTATE_SH)} carrier ${shq(arg)} 2>&1; } | tee -a ${shq(ROTATE_LOG)}`;
}

document.getElementById('simCountry').addEventListener('change', () => simFillCarriers(null));

document.getElementById('simApply').addEventListener('click', (ev) => withLoading(ev.currentTarget, async () => {
  const carSel = document.getElementById('simCarrier');
  const sel = carSel.value;
  if (!sel) { toast('Pilih operator dulu', { kind: 'warn' }); return; }
  const phantom = document.getElementById('simPhantom').checked ? '1' : '0';
  const opt = carSel.options[carSel.selectedIndex];
  const cid = (opt && opt.dataset ? opt.dataset.cid : '') || '';
  const r = await run(carrierCmd(`${sel}|${phantom}|${cid}`));
  finishRotate(r, 'SIM / operator');
  loadSim();
}));

document.getElementById('simOff').addEventListener('click', (ev) => withLoading(ev.currentTarget, async () => {
  const r = await run(carrierCmd('off'));
  finishRotate(r, 'SIM / operator');
  document.getElementById('simPhantom').checked = false;
  loadSim();
}));

async function loadTargets() {
  const ta = document.getElementById('tgtArea');
  const r = await safeExec(`cat ${shq(TARGETS)} 2>/dev/null || true`);
  ta.value = r.ok ? r.out : '';
  document.getElementById('tgtStatus').textContent = '';
}
document.getElementById('tgtReload').addEventListener('click', loadTargets);
document.getElementById('tgtSave').addEventListener('click', (ev) => withLoading(ev.currentTarget, async () => {
  const ta = document.getElementById('tgtArea');
  const content = ta.value.replace(/\r\n/g, '\n');
  const b64 = btoa(unescape(encodeURIComponent(content)));
  const cmd = `echo ${shq(b64)} | base64 -d > ${shq(TARGETS)} && chmod 0644 ${shq(TARGETS)}`;
  const r = await safeExec(cmd, 'target.txt tersimpan');
  if (r.ok) {
    const lines = content.split('\n').filter(l => l.trim() && !l.trim().startsWith('#')).length;
    document.getElementById('tgtStatus').textContent = `${lines} paket \u00b7 dimuat ulang saat spawn berikutnya`;
  }
}));

const ST_CAT = {
  identitas: 'Identitas', koherensi: 'Koherensi', vbmeta: 'Verified boot', build: 'Build',
  selinux: 'SELinux', rom: 'Emulator / ROM', root: 'Root', mount: 'Mount', hosts: 'Hosts',
  hooks: 'Hook per-app',
};
const ST_KIND = {
  PASS: 'st-pass', WARN: 'st-warn', FAIL: 'st-fail', INFO: 'st-info',
};

function parseSelftest(out) {
  const rows = [];
  let summary = null;
  for (const line of String(out || '').replace(/\r/g, '').split('\n')) {
    const s = line.match(/^SELFTEST\s+SUMMARY\s+(.*)$/);
    if (s) {
      const g = {};
      s[1].replace(/(\w+)=(\d+)/g, (_, k, v) => { g[k] = Number(v); return ''; });
      summary = g;
      continue;
    }
    const m = line.match(/^SELFTEST\s+(\S+)\s+(PASS|WARN|FAIL|INFO)\s*(.*)$/);
    if (m) rows.push({ cat: m[1], status: m[2], detail: m[3] });
  }
  return { rows, summary };
}

function renderSelftest(out) {
  const { rows, summary } = parseSelftest(out);
  const body = document.getElementById('stBody');
  const sum = document.getElementById('stSummary');
  if (!rows.length) {
    body.innerHTML = '<div class="empty">Tidak ada hasil uji. Coba jalankan lagi.</div>';
    sum.textContent = '';
    return;
  }
  body.innerHTML = rows.map(r => {
    const cls = ST_KIND[r.status] || ST_KIND.INFO;
    const cat = ST_CAT[r.cat] || r.cat;
    return `<div class="card st ${cls}">` +
      `<div class="st-head"><span class="st-badge">${escapeHtml(r.status)}</span>` +
      `<span class="name">${escapeHtml(cat)}</span></div>` +
      `<div class="desc">${escapeHtml(r.detail)}</div></div>`;
  }).join('');
  body.querySelectorAll('.card').forEach((el, i) => el.style.setProperty('--i', i));
  if (summary) {
    const p = summary.pass || 0, w = summary.warn || 0, f = summary.fail || 0, inf = summary.info || 0;
    sum.textContent = `${p} pass · ${w} warn · ${f} fail · ${inf} info`;
  } else {
    sum.textContent = '';
  }
}

async function runSelftest(showToast) {
  const body = document.getElementById('stBody');
  body.innerHTML = skLines(8);
  const r = await run(`${ENV} && sh ${shq(SELFTEST_SH)} 2>&1`);
  if (!r.ok) {
    const msg = (r.err && r.err.message) || 'error';
    body.innerHTML = `<div class="empty">Gagal menjalankan uji: ${escapeHtml(msg)}</div>`;
    document.getElementById('stSummary').textContent = '';
    if (showToast) toast(trimTitle(msg), { kind: 'error', detail: (r.err && (r.err.stdout || r.err.stderr)) || '' });
    return;
  }
  renderSelftest(r.out);
  if (showToast) {
    const { summary } = parseSelftest(r.out);
    const f = (summary && summary.fail) || 0, w = (summary && summary.warn) || 0, p = (summary && summary.pass) || 0;
    const kind = f > 0 ? 'error' : (w > 0 ? 'warn' : 'ok');
    toast(`Uji selesai · ${p} pass · ${w} warn · ${f} fail`, { kind, detail: r.out });
  }
}

async function loadSelftest() { return runSelftest(false); }

document.getElementById('stRun').addEventListener('click', (ev) =>
  withLoading(ev.currentTarget, () => runSelftest(true)));

async function loadLog() {
  const src = document.getElementById('logSrc').value;
  const body = document.getElementById('logBody');
  body.innerHTML = skLines(10);
  let cmd;
  if (src === 'action')  cmd = `tail -n 400 ${shq(ACTION_LOG)} 2>/dev/null || echo '(belum ada action.log \u2014 tekan "Acak perangkat baru" atau tombol Action di KSU/APatch)'`;
  else if (src === 'rotate') cmd = `tail -n 400 ${shq(ROTATE_LOG)} 2>/dev/null || echo '(belum ada rotate.log \u2014 tekan tombol Rotasi)'`;
  else if (src === 'session') cmd = `ls -t ${shq(MODDIR)}/debug/session-*.log 2>/dev/null | head -n 1 | xargs -r tail -n 400 || echo '(tidak ada session log \u2014 pasang varian debug)'`;
  else if (src === 'crashes') cmd = `tail -n 400 ${shq(MODDIR)}/debug/crashes.log 2>/dev/null || echo '(belum ada crashes.log)'`;
  else if (src === 'logcat') cmd = `logcat -d -t 200 -v time -s SandboxID:V SandboxIDCompanion:V 2>&1 | tail -n 200`;
  const r = await safeExec(cmd);
  const text = (r.ok ? r.out : (r.err && r.err.message) || 'error') || '(kosong)';
  body.innerHTML = renderLogHtml(text);
  body.scrollTop = body.scrollHeight;
}
document.getElementById('logRefresh').addEventListener('click', loadLog);
document.getElementById('logSrc').addEventListener('change', loadLog);

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function applyTheme(mode) {
  const root = document.documentElement;
  if (mode === 'light' || mode === 'dark') root.setAttribute('data-theme', mode);
  else root.removeAttribute('data-theme');
}
function currentTheme() {
  const attr = document.documentElement.getAttribute('data-theme');
  if (attr === 'light' || attr === 'dark') return attr;
  return (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) ? 'light' : 'dark';
}
function initTheme() {
  const btn = document.getElementById('themeBtn');
  if (!btn) return;
  btn.addEventListener('click', () => {
    const next = currentTheme() === 'light' ? 'dark' : 'light';
    applyTheme(next);
    try { localStorage.setItem('sbx-theme', next); } catch (e) {}
  });
}

(function boot() {
  initTheme();
  toastInit();
  wireTabs();
  moveIndicator();
  const nav = document.getElementById('nav');
  nav.addEventListener('scroll', moveIndicator);
  window.addEventListener('resize', moveIndicator);
  window.addEventListener('load', moveIndicator);
  const bridge = (typeof ksu !== 'undefined' && !!ksu.exec);
  const live = document.getElementById('live');
  if (live) {
    live.classList.add(bridge ? 'on' : 'off');
    live.title = bridge ? 'root bridge aktif' : 'root bridge tidak tersedia';
  }
  (async () => {
    const v = await run(`sed -n 's/^version=//p' ${shq(MODDIR)}/module.prop 2>/dev/null | head -n 1`);
    if (v.ok && v.out.trim()) document.getElementById('version').textContent = v.out.trim();
    await run(`mkdir -p ${shq(MODDIR)}/debug && touch ${shq(ROTATE_LOG)} ${shq(ACTION_LOG)}`);
    loadPersona();
  })();
})();
