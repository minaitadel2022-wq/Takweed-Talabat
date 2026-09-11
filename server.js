const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
// const { localISODate, localISOMonth } = require('./public/js/dateUtils');
// const { buildEditDetails } = require('./lib/auditDiff');
// const { hasPermission, sanitizePermissions, GRANTABLE_PERMISSION_KEYS } = require('./public/js/permissions');
const XLSXChart = require('xlsx-chart');

const app = express();
const PORT = process.env.PORT || 3000;

// Detect the machine's own LAN IP automatically instead of hardcoding one.
// Falls back to 0.0.0.0 (all interfaces) / localhost if nothing suitable is found.
function getLocalIP() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) return iface.address;
    }
  }
  return 'localhost';
}
const HOST = '0.0.0.0';
const DISPLAY_IP = process.env.HOST || getLocalIP();

// Where the JSON "database" files + backups live. Defaults to this folder for
// local/VPS use. On a cloud host with an ephemeral filesystem, set DATA_DIR to
// a mounted persistent volume (e.g. Render/Railway/Fly disks) so data survives
// restarts and redeploys — see README "النشر على أي كلاود".
const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : __dirname;
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const DATA_FILE = path.join(DATA_DIR, 'data.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const ACTIVITY_FILE = path.join(DATA_DIR, 'activity.json');
// Internal "notify a colleague about this alert" chat threads — see the
// "Notifications & Internal Chat" section further down for the full shape.
const CHATS_FILE = path.join(DATA_DIR, 'chats.json');
const BACKUP_DIR = path.join(DATA_DIR, 'backups');
// Where a user's saved/edited copy of a request's "العرض المالي" (offer) Word
// file lives, once they've uploaded one back (see the offer-doc routes below).
const OFFER_DOCS_DIR = path.join(DATA_DIR, 'offer-docs');
if (!fs.existsSync(OFFER_DOCS_DIR)) fs.mkdirSync(OFFER_DOCS_DIR, { recursive: true });
function offerDocPath(id) { return path.join(OFFER_DOCS_DIR, id + '.docx'); }
// Same folder/backup coverage as the financial offer above, just its own
// filename suffix so the two saved .docx files never collide.
function techOfferDocPath(id) { return path.join(OFFER_DOCS_DIR, id + '-tech.docx'); }

// Where product-photo uploads live, per request: product-images/<recordId>/<imageId>.<ext>
// Each request can carry several images (unlike the single offer .docx above),
// so metadata for the set (id/filename/mime/size/savedAt/savedBy) is kept on the
// record itself (rec.productImages) while the bytes live on disk here.
const PRODUCT_IMAGES_DIR = path.join(DATA_DIR, 'product-images');
if (!fs.existsSync(PRODUCT_IMAGES_DIR)) fs.mkdirSync(PRODUCT_IMAGES_DIR, { recursive: true });
function productImagesDir(recordId) { return path.join(PRODUCT_IMAGES_DIR, recordId); }
// "صور عينة للمنتج" — a second, separate photo set per request (e.g. photos of
// an actual physical sample, as opposed to صور المنتج which are usually
// catalog/product photos). Same storage shape as product images, just its own
// directory and its own field (rec.sampleImages) so the two never mix.
const SAMPLE_IMAGES_DIR = path.join(DATA_DIR, 'sample-images');
if (!fs.existsSync(SAMPLE_IMAGES_DIR)) fs.mkdirSync(SAMPLE_IMAGES_DIR, { recursive: true });
function sampleImagesDir(recordId) { return path.join(SAMPLE_IMAGES_DIR, recordId); }
const IMAGE_MIME_EXT = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'image/gif': 'gif' };
const MAX_IMAGES_PER_RECORD = 20;
// Light magic-byte sniff so an upload's actual bytes match the Content-Type it
// claims — mirrors the "PK" check already done for the offer .docx above.
function looksLikeImage(buf, mime) {
  if (!Buffer.isBuffer(buf) || buf.length < 4) return false;
  if (mime === 'image/jpeg') return buf[0] === 0xFF && buf[1] === 0xD8;
  if (mime === 'image/png') return buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4E && buf[3] === 0x47;
  if (mime === 'image/gif') return buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46;
  if (mime === 'image/webp') return buf.length >= 12 && buf.toString('ascii', 0, 4) === 'RIFF' && buf.toString('ascii', 8, 12) === 'WEBP';
  return false;
}

// ================= Security hardening =================
// Sets a set of protective HTTP response headers (no-sniff, no-clickjacking,
// hides "X-Powered-By: Express", etc). CSP is left off because this is a small
// single-file front-end app that relies on inline <script>/<style> tags — a
// strict CSP would break it without real security benefit for a trusted, local app.
app.use(helmet({ contentSecurityPolicy: false }));

// Gzip every response above ~1KB (the /api/records, /api/customers and
// /api/activity lists are the ones that actually matter here — they're the
// payloads that keep growing as more branches add more orders, so this is
// what keeps "loading the list" fast over a slow branch connection instead of
// getting slower as the business grows). Product images and the generated
// offer .docx are already compressed formats, so re-compressing them would
// just burn CPU for no size benefit. The live-update stream (/api/events) is
// excluded too — it's a long-lived stream of small text pings, not a payload
// worth compressing, and buffering it for gzip would work against the whole
// point of it being instant.
const COMPRESSIBLE_SKIP = /^\/api\/(records\/[^/]+\/(images|offer-doc)|events)/;
app.use(compression({
  filter: (req, res) => !COMPRESSIBLE_SKIP.test(req.path) && compression.filter(req, res)
}));

// Only trust the X-Forwarded-For header when the app actually sits behind a
// real reverse proxy / load balancer (Render, Railway, Fly, an Nginx in front
// of it, etc — set TRUST_PROXY=1 in that case). Trusting it unconditionally
// on a server exposed directly to the internet lets anyone spoof their own
// X-Forwarded-For header to a fresh value on every request, which resets their
// rate-limit bucket each time and defeats the login brute-force protection.
if (process.env.TRUST_PROXY === '1' || process.env.TRUST_PROXY === 'true') {
  app.set('trust proxy', 1);
}

// Hard cap on request body size so nobody can crash the server with a giant payload.
app.use(express.json({ limit: '1mb' }));
// public/vendor/xlsx.core.min.js is a large (400KB+) third-party library that
// never changes between deploys of this project — cache it for a month so
// returning visits don't re-download it, while everything else in public/
// (index.html, public/js/*) keeps the default no-explicit-cache behaviour
// since those DO change whenever this app is updated and must never go stale
// in someone's browser after a deploy.
app.use('/vendor', express.static(path.join(__dirname, 'public', 'vendor'), { maxAge: '30d', immutable: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Brute-force protection on login: max 10 attempts per 15 minutes per IP.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'محاولات دخول كثيرة جداً، من فضلك حاول مرة أخرى بعد شوية' }
});
// General API rate limit as a safety net against abuse/DoS.
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'عدد كبير من الطلبات، من فضلك حاول لاحقاً' }
});
app.use('/api', apiLimiter);

// ================= JSON "database" helpers (in-memory cache + async persist) =================
// Why: the old version did a synchronous readFileSync+JSON.parse AND a
// synchronous writeFileSync+JSON.stringify on EVERY single API call (and a
// second full round-trip for activity.json via logActivity right after). Those
// are blocking calls, so while one branch's request was reading/parsing/
// writing the whole file, every other branch's request — even a simple GET —
// was frozen waiting behind it on Node's single thread. As the number of
// orders grows, data.json grows, so every request (not just writes) kept
// getting slower for everybody, worst of all under concurrent multi-branch use.
//
// Fix: load each JSON "table" once into memory. Reads never touch disk at all
// from then on. Writes update the in-memory copy immediately (so the very
// next request already sees the change) and are persisted to disk in the
// background: debounced (a burst of changes — e.g. saving a record, then
// logging its activity — collapses into one disk write) and queued per file
// (writes to the same file never overlap/corrupt each other) using async,
// non-blocking fs calls, and written atomically (temp file + rename) so a
// crash mid-write can never leave a half-written file on disk.
const DEBOUNCE_MS = 150;
const fileCache = new Map();     // absolute path -> live JS object (source of truth)
const pendingWrite = new Map();  // absolute path -> pending setTimeout handle
const writeChain = new Map();    // absolute path -> promise chain (serializes disk writes)

function loadJSONSync(file, fallback) {
  if (!fs.existsSync(file)) fs.writeFileSync(file, JSON.stringify(fallback, null, 2));
  return JSON.parse(fs.readFileSync(file, 'utf-8'));
}
function persistToDisk(file) {
  if (!fileCache.has(file)) return Promise.resolve();
  const json = JSON.stringify(fileCache.get(file), null, 2);
  const tmp = file + '.tmp' + process.pid;
  const prev = writeChain.get(file) || Promise.resolve();
  const next = prev
    .then(() => fs.promises.writeFile(tmp, json))
    .then(() => fs.promises.rename(tmp, file))
    .catch(e => console.error(`⚠ فشل حفظ ${path.basename(file)} على القرص:`, e.message));
  writeChain.set(file, next);
  return next;
}
function scheduleWrite(file) {
  if (pendingWrite.has(file)) return; // a write is already scheduled — this change will ride along with it
  const t = setTimeout(() => { pendingWrite.delete(file); persistToDisk(file); }, DEBOUNCE_MS);
  t.unref(); // don't keep the process alive just for this timer
  pendingWrite.set(file, t);
}
// Forces any pending change for one file to disk right now (skips the debounce
// wait). Used before backups and on shutdown so nothing recent is ever missed.
function flushWrite(file) {
  if (pendingWrite.has(file)) { clearTimeout(pendingWrite.get(file)); pendingWrite.delete(file); }
  return persistToDisk(file);
}
function flushAllWrites() {
  return Promise.all([DATA_FILE, USERS_FILE, ACTIVITY_FILE, CHATS_FILE].map(flushWrite));
}
function readJSON(file, fallback) {
  if (!fileCache.has(file)) fileCache.set(file, loadJSONSync(file, fallback));
  return fileCache.get(file);
}
function writeJSON(file, data) {
  fileCache.set(file, data);
  scheduleWrite(file);
}
// A record used to carry a single البند (item/description/brand) plus a single
// quoteQuantity/quoteUnitPrice/quoteValue. It now carries an `items` array so a
// request/quote can hold several بنود. Any record saved before this change
// (or loaded from an older backup) is migrated into a one-item array built
// from its old fields, so nothing on disk needs to be touched by hand.
// Runs once per record, right when data.json is first loaded into memory
// (not on every read anymore — the in-memory copy is already normalized).
function normalizeRecord(rec) {
  if (!Array.isArray(rec.items) || rec.items.length === 0) {
    rec.items = [{
      item: rec.item || '',
      description: rec.description || '',
      brand: rec.brand || '',
      quantity: rec.quoteQuantity || '',
      unitPrice: rec.quoteUnitPrice || '',
      total: rec.quoteValue || '',
      priced: false
    }];
  }
  // Records saved before the per-item "priced" checkbox existed won't have it
  // on their items — default every item to false so the pricing-progress UI
  // never sees undefined.
  rec.items.forEach(it => {
    if (it.priced === undefined) it.priced = false;
    if (it.colorTag === undefined) it.colorTag = '';
    if (it.itemNotes === undefined) it.itemNotes = '';
    // Each بند used to share the request's single followupStatus/codeArrivalDate —
    // now every item tracks its own, independently of its siblings, so one item
    // being priced/closed doesn't affect the others still under study. Default
    // pre-existing items to the request's own values at migration time (a
    // reasonable starting point), then they diverge as each is updated on its own.
    if (it.followupStatus === undefined) it.followupStatus = rec.followupStatus || 'تحت التسعير';
    if (it.codeArrivalDate === undefined) it.codeArrivalDate = rec.codeArrivalDate || '';
  });
  // Records saved before "تاريخ وصول الكود من المكتب الفني" / "تاريخ عمل عرض السعر"
  // existed won't have these fields — default them so the UI never sees undefined.
  if (rec.codeArrivalDate === undefined) rec.codeArrivalDate = '';
  if (rec.quoteDate === undefined) rec.quoteDate = '';
  if (rec.closedAt === undefined) rec.closedAt = '';
  if (rec.closedBy === undefined) rec.closedBy = '';
  if (rec.closeReason === undefined) rec.closeReason = '';
  // Records won before this field existed have no exact win date — leave
  // blank rather than guess; the average-time-to-win report only counts
  // records that actually have one, and states that plainly.
  if (rec.wonAt === undefined) rec.wonAt = '';
  // Records saved before the "تم إرسال العرض إلى العميل" checkbox existed
  // won't have this field — default to false so the counter and checkbox
  // state are never undefined.
  if (rec.sentToCustomer === undefined) rec.sentToCustomer = false;
  // Same for the two manual follow-up notes recorded after sending a quote.
  if (rec.customerResponse === undefined) rec.customerResponse = '';
  if (rec.actionTaken === undefined) rec.actionTaken = '';
  // Records won before the "الموقف الحالي" note existed won't have it either.
  if (rec.poCurrentStatus === undefined) rec.poCurrentStatus = '';
  // Records won before the PO supply-type choice existed won't have it either.
  if (rec.poSupplyType === undefined) rec.poSupplyType = '';
  return rec;
}
const readData = () => {
  if (!fileCache.has(DATA_FILE)) {
    const d = loadJSONSync(DATA_FILE, { records: [], seq: 0 });
    d.records = d.records.map(normalizeRecord);
    fileCache.set(DATA_FILE, d);
  }
  return fileCache.get(DATA_FILE);
};
// /api/customers aggregates over every record — cheap now that records live in
// RAM, but still O(records), and it was being redone from scratch on every
// single request. Only 4 possible "views" of it exist (super admin sees all
// branches; anyone else sees only their own), so memoize per view and
// invalidate whenever a record actually changes — the common case (viewing
// the customers list, or several branches doing so at once, with no new
// orders in between) then costs nothing.
// ================= Live updates (Server-Sent Events) =================
// The problem this solves: two branches create a request seconds apart and
// the codes come out perfectly sequential on the server (confirmed under
// concurrent load — see the caching/queued-write section above), but a
// browser that was already looking at the list before the second request
// landed had no way to know about it until the page was refreshed — so its
// table looked like it had a gap in the coding. Rather than have every open
// tab poll "did anything change?" over and over, each tab holds one open
// connection and the server pushes a tiny "something changed" signal down it
// the instant a write actually happens. The tab then quietly re-fetches
// whichever list(s) that affects through the normal branch-scoped API and
// re-renders — nothing except a type name ever goes over this connection, so
// it doesn't change what any user is allowed to see.
const sseClients = new Set();
const ssePending = new Set();   // event types waiting to be flushed (debounced)
let sseFlushTimer = null;
function broadcastEvent(type) {
  ssePending.add(type);
  if (sseFlushTimer) return; // a flush is already scheduled — this rides along with it
  sseFlushTimer = setTimeout(() => {
    const types = [...ssePending];
    ssePending.clear();
    sseFlushTimer = null;
    for (const t of types) {
      const payload = `event: update\ndata: ${JSON.stringify({ type: t })}\n\n`;
      for (const client of sseClients) { try { client.write(payload); } catch (e) { /* dead connection, req.on('close') will clean it up */ } }
    }
  }, 200);
  sseFlushTimer.unref();
}

const customersCache = new Map(); // scope key ('ALL' or a branch code) -> { customers: [...] }
const writeData = (d) => { customersCache.clear(); writeJSON(DATA_FILE, d); broadcastEvent('records'); };
const readUsers = () => readJSON(USERS_FILE, { users: [] });
const writeUsers = (d) => { writeJSON(USERS_FILE, d); broadcastEvent('users'); };
const readActivity = () => readJSON(ACTIVITY_FILE, { log: [] });
const writeActivity = (d) => { writeJSON(ACTIVITY_FILE, d); broadcastEvent('activity'); };
const readChats = () => readJSON(CHATS_FILE, { threads: [] });
// Broadcasts on every new message so an open "المحادثات" list / unread badge
// on any other tab updates immediately. Marking a thread as read (see
// GET /api/chats/:id) persists via writeJSON directly instead, since that
// happens on every open and doesn't need to ping every other tab.
const writeChats = (d) => { writeJSON(CHATS_FILE, d); broadcastEvent('chats'); };

// Always compute "today" in Egypt's timezone (Africa/Cairo), regardless of what
// timezone the server's OS/host is set to. Most cloud hosts (Render, Railway,
// Fly, Replit...) run in UTC by default, which is 2-3 hours behind Cairo —
// without this, any request created in roughly the first few hours of the
// Cairo day (e.g. after midnight) would get stamped with *yesterday's* date
// (still "yesterday" in UTC) instead of today's.
const APP_TIMEZONE = 'Africa/Cairo';
const cairoDateFormatter = new Intl.DateTimeFormat('en-CA', { timeZone: APP_TIMEZONE, year: 'numeric', month: '2-digit', day: '2-digit' });
function todayISO() { return cairoDateFormatter.format(new Date()); } // -> "YYYY-MM-DD" in Cairo time
// Loose but safe check for a plain "YYYY-MM-DD" date string coming from an
// <input type="date">. Used to sanitize per-item dates without over-engineering
// a full calendar validator — good enough to keep obviously-garbage input out.
function isValidISODate(v) { return typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v); }

// Branch codes a user can be assigned, and the request-coding prefix each one produces.
const BRANCH_CODES = ['SP', 'ACH', 'AXH'];

// Given a record, return the branch it belongs to. Prefers the explicit
// branchCode field (set on every record created from now on); falls back to
// parsing it from the coding prefix for older records saved before this field
// existed, so nothing breaks on upgrade.
function recordBranch(r) {
  if (r.branchCode && BRANCH_CODES.includes(r.branchCode)) return r.branchCode;
  const m = /^([A-Za-z]+)\d+$/.exec(r.code || '');
  return (m && BRANCH_CODES.includes(m[1])) ? m[1] : null;
}

// Restrict a list of records to the ones the given user is allowed to see.
// Three roles now: "super_admin" sees/edits/deletes across every branch with
// no restriction at all. "admin" (branch admin) and "viewer" (read-only) are
// both scoped to their own branch only — the difference between them (and
// between individual users of the same role) is which specific permissions
// they hold, see public/js/permissions.js and requirePermission() below —
// not visibility, which this function alone controls.
function scopeRecords(user, records) {
  if (user.role === 'super_admin') return records;
  return records.filter(r => recordBranch(r) === user.branchCode);
}

// Sequential coding per branch: SP1, SP2 ... ACH1, ACH2 ... AXH1, AXH2 ...
// (no date, no dashes, no leading zeros). Each branch keeps its own counter so
// numbering never repeats or collides across branches, even after deletions.
function genCode(data, branchCode) {
  const prefix = BRANCH_CODES.includes(branchCode) ? branchCode : 'SP';
  if (!data.seqByBranch) data.seqByBranch = {};
  if (!data.seqByBranch[prefix]) {
    // migrate: if this is the first time we generate a sequential code for this branch,
    // start after the highest existing "<prefix><number>" code so we never collide.
    const regex = new RegExp('^' + prefix + '(\\d+)$');
    const maxExisting = data.records.reduce((max, r) => {
      const m = regex.exec(r.code || '');
      return m ? Math.max(max, parseInt(m[1], 10)) : max;
    }, 0);
    data.seqByBranch[prefix] = maxExisting;
  }
  data.seqByBranch[prefix] += 1;
  return prefix + data.seqByBranch[prefix];
}

// Sequential coding for price offers, scoped per branch: SPOffer1, SPOffer2 ...
// ACHOffer1 ... AXHOffer1 ... — assigned the moment a request moves from
// "متابعة الطلبات" (followup) into "عروض الأسعار" (quotes). Each branch keeps its
// own counter, exactly like genCode() above, so offer numbering stays sequential
// within a branch's own view instead of having gaps from other branches' offers.
function genOfferCode(data, branchCode) {
  const prefix = BRANCH_CODES.includes(branchCode) ? branchCode : 'SP';
  if (!data.offerSeqByBranch) data.offerSeqByBranch = {};
  if (!data.offerSeqByBranch[prefix]) {
    const regex = new RegExp('^' + prefix + 'Offer(\\d+)$');
    const maxExisting = data.records.reduce((max, r) => {
      const m = regex.exec(r.offerCode || '');
      return m ? Math.max(max, parseInt(m[1], 10)) : max;
    }, 0);
    data.offerSeqByBranch[prefix] = maxExisting;
  }
  data.offerSeqByBranch[prefix] += 1;
  return prefix + 'Offer' + data.offerSeqByBranch[prefix];
}

// ================= Password hashing (Node core crypto, no deps) =================
function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}
function makeSalt() { return crypto.randomBytes(16).toString('hex'); }
function verifyPassword(password, salt, hash) {
  const attempt = hashPassword(password, salt);
  const a = Buffer.from(attempt, 'hex');
  const b = Buffer.from(hash, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// ================= First-run seeding =================
// If USERS_FILE doesn't exist yet — e.g. the very first deploy on a fresh cloud
// volume, where no users.json ships with the code — create the one default
// super-admin account so there's always a way to log in. Credentials are
// overridable via env vars (ADMIN_USERNAME / ADMIN_PASSWORD) so a future
// deploy can set different ones without touching this file.
// This runs no matter where DATA_DIR points, so it isn't only "just works"
// locally — it also "just works" the first time a persistent volume is empty.
// Only ONE account is ever seeded here — there is no separate generic "admin"
// account created alongside it, so there's nothing else to demote later.
if (!fs.existsSync(USERS_FILE)) {
  const seedUsername = process.env.ADMIN_USERNAME || 'Ultra Admin';
  const seedPassword = process.env.ADMIN_PASSWORD || 'ForOnlyUL@@8246OnlyULCan';
  const salt = makeSalt();
  writeJSON(USERS_FILE, {
    users: [{
      // protected:true marks this as the one "ultra admin" account — see the
      // protection rules right below requireSuperAdmin: no other account,
      // even another super_admin, can see it in the users list, edit/change
      // its password, delete it, or trigger a backup. Only this account
      // itself can do any of that. This flag is never exposed to the
      // POST/PATCH /api/users bodies, so it can't be granted to any other
      // account through the API — only by editing users.json directly.
      id: 'u1', username: seedUsername, name: seedUsername, role: 'super_admin', branchCode: 'SP',
      protected: true,
      salt, hash: hashPassword(seedPassword, salt)
    }]
  });
  console.log(`✔ تم إنشاء مستخدم مدير عام محمي (Ultra Admin) افتراضي: ${seedUsername}`);
  console.log(`  ⚠ لو محتاج تغيّر اسم المستخدم أو كلمة المرور دي مستقبلاً، سجّل الدخول بيه وغيّرها بنفسك من صفحة "المستخدمون والصلاحيات"، أو احذف users.json وحدد ADMIN_USERNAME / ADMIN_PASSWORD قبل أول تشغيل.`);
}

// ================= Protected-admin migration (for installs before this flag existed) =================
// If users.json already existed from before the `protected` flag was
// introduced, nobody has it set yet. In that case, if there's exactly one
// account matching the configured ultra-admin username (default "Ultra
// Admin") with role super_admin, mark that one protected automatically so
// upgrading doesn't require manually editing users.json. If that account
// can't be found unambiguously, nothing is marked — better to leave everyone
// unprotected than to guess wrong and protect the wrong account.
// Also re-run right after a restore (see /api/backup/restore below) — a
// restored users.json might come from an old backup taken before this flag
// existed, and this is what re-establishes the protected account afterward.
function ensureProtectedAdmin() {
  const users = readUsers();
  if (!users.users.length) return;
  if (users.users.some(u => u.protected)) return;
  const seedUsername = process.env.ADMIN_USERNAME || 'Ultra Admin';
  const candidates = users.users.filter(u => u.username === seedUsername && u.role === 'super_admin');
  if (candidates.length === 1) {
    candidates[0].protected = true;
    writeUsers(users);
    console.log(`✔ تم تحديد "${candidates[0].username}" كحساب مدير محمي (Ultra Admin) تلقائياً`);
  }
}
ensureProtectedAdmin();

// ================= Role migration (for installs that predate super_admin) =================
// Older data files only ever had two roles: "admin" (full control) and "viewer"
// (read-only). The new model has three: "super_admin" (every branch, full
// control), "admin" (branch admin — codes/edits their own branch only), and
// "viewer" (read-only, own branch only). On the first run after upgrading, if
// nobody is a super_admin yet, promote the first existing "admin" account (or
// failing that, the first account at all) so the system always has someone with
// full control. Everyone else keeps their current role/branch unchanged.
(function migrateToSuperAdmin() {
  const users = readUsers();
  if (!users.users.length) return;
  const hasSuperAdmin = users.users.some(u => u.role === 'super_admin');
  if (hasSuperAdmin) return;
  const candidate = users.users.find(u => u.role === 'admin') || users.users[0];
  candidate.role = 'super_admin';
  writeUsers(users);
  console.log(`✔ ترقية المستخدم "${candidate.username}" إلى مدير عام (Super Admin) تلقائياً بعد تحديث النظام`);
})();

// ================= Sessions (in-memory token store) =================
// token -> { user: {...}, expiresAt: <ms timestamp> }
const sessions = {};
const SESSION_TTL_MS = 5 * 60 * 1000; // 5 minutes of inactivity -> auto logout (server-side backstop; the client also enforces this with its own idle timer + a lock screen)

function publicUser(u) { return { id: u.id, username: u.username, name: u.name, role: u.role, branchCode: u.branchCode || 'SP', protected: !!u.protected, permissions: (u.permissions && typeof u.permissions === 'object') ? u.permissions : {} }; }

// Periodically sweep expired sessions out of memory.
setInterval(() => {
  const now = Date.now();
  for (const token of Object.keys(sessions)) {
    if (sessions[token].expiresAt < now) delete sessions[token];
  }
}, 10 * 60 * 1000).unref();

// ================= Activity log =================
function logActivity(user, action, entityType, entityCode, details) {
  const activity = readActivity();
  activity.log.unshift({
    id: 'a' + Date.now() + Math.floor(Math.random() * 1000),
    timestamp: new Date().toISOString(),
    userName: user ? user.name : 'غير معروف',
    userRole: user ? user.role : '',
    action,
    entityType,
    entityCode: entityCode || '',
    details: details || ''
  });
  // keep log from growing unbounded in this simple prototype
  if (activity.log.length > 2000) activity.log = activity.log.slice(0, 2000);
  writeActivity(activity);
}

// ================= Auth middleware =================
function requireAuth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const session = token && sessions[token];
  if (!session || session.expiresAt < Date.now()) {
    if (session) delete sessions[token]; // clean up expired token
    return res.status(401).json({ error: 'انتهت الجلسة، من فضلك سجّل الدخول تاني' });
  }
  // sliding expiry: every authenticated request extends the session
  session.expiresAt = Date.now() + SESSION_TTL_MS;
  // Refresh from the live user record on every request instead of trusting
  // the snapshot taken at login — readUsers() is an in-memory cache (see
  // readJSON), not a disk read, so this is cheap. This is what makes a role
  // or permissions change by an admin take effect on the person's very next
  // request instead of only after they log out and back in — and it also
  // means a deleted account's sessions stop working immediately.
  const liveUser = readUsers().users.find(u => u.id === session.user.id);
  if (!liveUser) { delete sessions[token]; return res.status(401).json({ error: 'هذا الحساب لم يعد موجوداً' }); }
  session.user = publicUser(liveUser);
  req.user = session.user;
  req.token = token;
  next();
}
// Express middleware factory: blocks the request with 403 unless the logged-in
// user has the named permission (see public/js/permissions.js — the single
// source of truth for what each key means and who gets it by default).
function requirePermission(key) {
  return (req, res, next) => {
    if (!hasPermission(req.user, key)) return res.status(403).json({ error: 'لا تملك صلاحية القيام بهذا الإجراء' });
    next();
  };
}
// Full, unrestricted control: user management, deleting records (any branch),
// and system-level actions like backups. Only "super_admin" passes this.
function requireSuperAdmin(req, res, next) {
  if (req.user.role !== 'super_admin') return res.status(403).json({ error: 'هذا الإجراء يتطلب صلاحية مدير عام (Super Admin)' });
  next();
}
// A level above super_admin: the single protected "Ultra Admin" account
// (users.json entry with protected:true). Used for actions that must stay
// exclusive to that one account even from other super_admins — right now
// that's backups. See the protection rules further down (GET/PATCH/DELETE
// /api/users) for how the account itself stays invisible/untouchable to
// everyone else too.
function requireUltraAdmin(req, res, next) {
  if (!req.user.protected) return res.status(403).json({ error: 'هذا الإجراء متاح فقط لحساب المدير المحمي (Ultra Admin)' });
  next();
}

// ================= Offer document (Word) generation =================
// "العرض المالي": fills the company's Word offer template with a request's
// data (date, customer, branch/company, offer number, item, total, notes).
// The template lives at templates/offer-template.docx with {{TOKEN}} markers
// inside word/document.xml. No external docx library is used — lib/minizip.js
// is a small dependency-free zip reader/writer, and filling in the template is
// just a text substitution on that one XML file inside the zip.
const OFFER_TEMPLATE_PATH = path.join(__dirname, 'templates', 'offer-template.docx');
let offerTemplateEntriesCache = null;
function loadOfferTemplateEntries() {
  if (!offerTemplateEntriesCache) {
    if (!fs.existsSync(OFFER_TEMPLATE_PATH)) throw new Error('قالب العرض المالي غير موجود على السيرفر (templates/offer-template.docx)');
    offerTemplateEntriesCache = unzip(fs.readFileSync(OFFER_TEMPLATE_PATH));
  }
  return offerTemplateEntriesCache;
}
function escapeXml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, ch => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' }[ch]
  ));
}
// "2026-08-20" -> "20 / 08 / 2026" (matches how the template's date line reads)
function formatOfferDate(iso) {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(iso || '');
  return m ? `${m[3]} / ${m[2]} / ${m[1]}` : '';
}
// Builds one <w:tr> of the items table (in the template's own XML) for a
// single بند, filling in its serial number + the four token cells.
function buildItemRowXml(rowTemplate, index, item) {
  let row = rowTemplate.replace('<w:t>1</w:t>', `<w:t>${escapeXml(index)}</w:t>`);
  const itemText = (item.item || '') + (item.description ? (' - ' + item.description) : '');
  row = row
    .split('{{ITEM}}').join(escapeXml(itemText))
    .split('{{QUANTITY}}').join(escapeXml(item.quantity || ''))
    .split('{{UNIT_PRICE}}').join(escapeXml(item.unitPrice || ''))
    .split('{{TOTAL}}').join(escapeXml(item.total || ''));
  return row;
}
function buildOfferDocx(rec) {
  const entries = loadOfferTemplateEntries();
  let xml = entries.get('word/document.xml').toString('utf-8');

  const items = (rec.items && rec.items.length)
    ? rec.items
    : [{ item: rec.item || '', description: rec.description || '', quantity: '', unitPrice: '', total: '' }];

  // The template has exactly one item row (containing {{ITEM}}/{{QUANTITY}}/
  // {{UNIT_PRICE}}/{{TOTAL}}) — clone it once per بند so the table lists every
  // item instead of just one, then (for more than one item) append a final
  // "الإجمالي الكلي" row using that same row shape.
  const itemTokenIdx = xml.indexOf('{{ITEM}}');
  if (itemTokenIdx !== -1) {
    // NOTE: search for the exact "<w:tr>" opening tag, not just "<w:tr" — that
    // shorter prefix also matches "<w:trPr>" (the row-properties tag nested
    // right inside it) and would chop off the real wrapping <w:tr>.
    const rowStart = xml.lastIndexOf('<w:tr>', itemTokenIdx);
    const rowEnd = xml.indexOf('</w:tr>', itemTokenIdx) + '</w:tr>'.length;
    const rowTemplate = xml.slice(rowStart, rowEnd);

    let rowsXml = items.map((it, i) => buildItemRowXml(rowTemplate, i + 1, it)).join('');

    if (items.length > 1) {
      const grandTotal = items.reduce((s, it) => s + (parseFloat(it.total) || 0), 0);
      rowsXml += buildItemRowXml(rowTemplate, '', { item: 'الإجمالي الكلي لكل البنود', description: '', quantity: '', unitPrice: '', total: grandTotal });
    }

    xml = xml.slice(0, rowStart) + rowsXml + xml.slice(rowEnd);
  }

  const values = {
    '{{DATE}}': formatOfferDate(rec.dateCreated),
    '{{CUSTOMER}}': rec.customer || '',
    '{{COMPANY}}': rec.company || '',
    '{{OFFER_NO}}': rec.offerCode || '',
    // "ملاحظات" at the end of the document = the notes typed in the "تحويل إلى
    // عرض سعر" / "تعديل عرض السعر" form (rec.quoteNotes) — the quote-stage
    // notes only. The original request's notes (rec.notes) and the follow-up
    // notes (rec.followupNotes) are internal and must never appear on the
    // financial offer document.
    '{{NOTES}}': rec.quoteNotes || ''
  };
  for (const [token, value] of Object.entries(values)) {
    xml = xml.split(token).join(escapeXml(value));
  }
  const outEntries = [];
  for (const [name, data] of entries) {
    outEntries.push({ name, data: name === 'word/document.xml' ? Buffer.from(xml, 'utf-8') : data });
  }
  return zip(outEntries);
}

// "العرض الفني": the same offer template as buildOfferDocx above, but stripped
// down for a technical (non-pricing) audience — the items table keeps only
// the serial number and البيان (item description) columns (الكمية / سعر
// الوحدة / الإجمالي removed), and the whole "الشروط العامة" section is
// removed entirely. Column removal is done generically (by counting and
// merging <w:tc>/<w:gridCol> widths) rather than by hardcoding this
// template's exact widths, so it keeps working if the template is edited.
function extractTopLevelCells(rowXml) {
  const cells = [];
  const re = /<w:tc>[\s\S]*?<\/w:tc>/g;
  let m;
  while ((m = re.exec(rowXml))) cells.push(m[0]);
  return cells;
}
// Keeps the first n cells of a table row, merging the width of every dropped
// cell into the last kept one so the table still spans the full page width
// instead of leaving a visible gap where the removed columns used to be.
function keepFirstNCellsMergingWidth(rowXml, n) {
  const firstTcIdx = rowXml.indexOf('<w:tc>');
  const prefix = rowXml.slice(0, firstTcIdx); // '<w:tr>...<w:trPr>...</w:trPr>'
  const cells = extractTopLevelCells(rowXml);
  const widths = cells.map(c => { const m = /<w:tcW w:w="(\d+)"/.exec(c); return m ? parseInt(m[1], 10) : 0; });
  const kept = cells.slice(0, n);
  const mergedWidth = widths.slice(n - 1).reduce((a, b) => a + b, 0);
  kept[n - 1] = kept[n - 1].replace(/<w:tcW w:w="\d+"/, `<w:tcW w:w="${mergedWidth}"`);
  return prefix + kept.join('') + '</w:tr>';
}
function keepFirstNGridCols(gridXml, n) {
  const cols = gridXml.match(/<w:gridCol[^>]*\/>/g) || [];
  const widths = cols.map(c => { const m = /w:w="(\d+)"/.exec(c); return m ? parseInt(m[1], 10) : 0; });
  const kept = cols.slice(0, n);
  const mergedWidth = widths.slice(n - 1).reduce((a, b) => a + b, 0);
  kept[n - 1] = kept[n - 1].replace(/w:w="\d+"/, `w:w="${mergedWidth}"`);
  return '<w:tblGrid>' + kept.join('') + '</w:tblGrid>';
}
// Applies text replacements only inside the one <w:p>...</w:p> paragraph that
// contains anchorText — not document-wide — since a single word (e.g. "عرض")
// can legitimately appear elsewhere in the template (headings, etc.) and must
// stay untouched there. If anchorText isn't found, xml is returned as-is.
function replaceInParagraphContaining(xml, anchorText, replacements) {
  const idx = xml.indexOf(anchorText);
  if (idx === -1) return xml;
  const pStart = Math.max(xml.lastIndexOf('<w:p>', idx), xml.lastIndexOf('<w:p ', idx));
  const pEnd = xml.indexOf('</w:p>', idx) + '</w:p>'.length;
  if (pStart === -1 || pEnd === -1) return xml;
  let para = xml.slice(pStart, pEnd);
  for (const [from, to] of replacements) para = para.split(from).join(to);
  return xml.slice(0, pStart) + para + xml.slice(pEnd);
}
function buildTechnicalOfferDocx(rec) {
  const entries = loadOfferTemplateEntries();
  const xml = entries.get('word/document.xml').toString('utf-8');

  const items = (rec.items && rec.items.length)
    ? rec.items
    : [{ item: rec.item || '', description: rec.description || '' }];

  const itemTokenIdx = xml.indexOf('{{ITEM}}');
  if (itemTokenIdx === -1) throw new Error('قالب العرض غير متوافق مع توليد العرض الفني');

  const tblStart = xml.lastIndexOf('<w:tbl>', itemTokenIdx);
  const tblGridStart = xml.indexOf('<w:tblGrid>', tblStart);
  const tblGridEnd = xml.indexOf('</w:tblGrid>', tblGridStart) + '</w:tblGrid>'.length;
  const headerRowStart = xml.indexOf('<w:tr>', tblGridEnd);
  const headerRowEnd = xml.indexOf('</w:tr>', headerRowStart) + '</w:tr>'.length;
  const rowStart = xml.lastIndexOf('<w:tr>', itemTokenIdx);
  const rowEnd = xml.indexOf('</w:tr>', itemTokenIdx) + '</w:tr>'.length;
  const tblEnd = xml.indexOf('</w:tbl>', itemTokenIdx) + '</w:tbl>'.length;

  const KEEP_COLS = 2; // م + البيان only
  const newGridXml = keepFirstNGridCols(xml.slice(tblGridStart, tblGridEnd), KEEP_COLS);
  const newHeaderRowXml = keepFirstNCellsMergingWidth(xml.slice(headerRowStart, headerRowEnd), KEEP_COLS);
  const rowTemplate = keepFirstNCellsMergingWidth(xml.slice(rowStart, rowEnd), KEEP_COLS);

  // No quantity/price/total columns left to fill in, and — unlike
  // buildOfferDocx — no "الإجمالي الكلي" row either, since there's nothing
  // left to total.
  const rowsXml = items.map((it, i) => {
    let row = rowTemplate.replace('<w:t>1</w:t>', `<w:t>${escapeXml(i + 1)}</w:t>`);
    const itemText = (it.item || '') + (it.description ? (' - ' + it.description) : '');
    return row.split('{{ITEM}}').join(escapeXml(itemText));
  }).join('');

  let newXml =
    xml.slice(0, tblGridStart) + newGridXml +
    xml.slice(tblGridEnd, headerRowStart) + newHeaderRowXml +
    xml.slice(headerRowEnd, rowStart) + rowsXml +
    xml.slice(rowEnd, tblEnd);

  // Strip "الشروط العامة" — its heading paragraph and the whole terms table
  // right after it — entirely out of the technical offer.
  let rest = xml.slice(tblEnd);
  const termsIdx = rest.indexOf('الشروط العامة');
  if (termsIdx !== -1) {
    const headingStart = Math.max(rest.lastIndexOf('<w:p>', termsIdx), rest.lastIndexOf('<w:p ', termsIdx));
    const termsTblStart = rest.indexOf('<w:tbl>', termsIdx);
    const termsTblEnd = termsTblStart !== -1 ? rest.indexOf('</w:tbl>', termsTblStart) + '</w:tbl>'.length : -1;
    if (headingStart !== -1 && termsTblEnd !== -1) {
      rest = rest.slice(0, headingStart) + rest.slice(termsTblEnd);
    }
  }
  newXml += rest;

  // "عرض سعرنا المرفق" -> "العرض الفني المرفق" — technical-offer-only wording,
  // scoped to this one intro paragraph (see replaceInParagraphContaining) so
  // it never touches "عرض" elsewhere in the document (e.g. the offer-number
  // heading just below). Each word is its own <w:t> run in the template, and
  // this maps word-for-word onto the existing three runs — "عرض"->"العرض",
  // "سعرنا"->"الفني", "المرفق" stays as-is — so no run/spacing structure changes.
  newXml = replaceInParagraphContaining(newXml, 'يشرفنا', [
    ['<w:t>عرض</w:t>', '<w:t>العرض</w:t>'],
    ['<w:t>سعرنا</w:t>', '<w:t>الفني</w:t>']
  ]);
  // "عرض اسعار رقم {{OFFER_NO}}" -> "عرض فني رقم {{OFFER_NO}}" — only the
  // middle word changes; "عرض" and "رقم" already read correctly either way.
  // Anchored on the (unique) {{OFFER_NO}} token so this never touches the
  // "عرض" in the paragraph replaced just above.
  newXml = replaceInParagraphContaining(newXml, '{{OFFER_NO}}', [
    ['<w:t>اسعار</w:t>', '<w:t>فني</w:t>']
  ]);

  const values = {
    '{{DATE}}': formatOfferDate(rec.dateCreated),
    '{{CUSTOMER}}': rec.customer || '',
    '{{COMPANY}}': rec.company || '',
    '{{OFFER_NO}}': rec.offerCode || '',
    '{{NOTES}}': rec.quoteNotes || ''
  };
  for (const [token, value] of Object.entries(values)) {
    newXml = newXml.split(token).join(escapeXml(value));
  }

  const outEntries = [];
  for (const [name, data] of entries) {
    outEntries.push({ name, data: name === 'word/document.xml' ? Buffer.from(newXml, 'utf-8') : data });
  }
  return zip(outEntries);
}

// ================= Monthly Sales Manager Report (Word) generation =================
// "التقرير الشهري لمدير المبيعات": same template-substitution approach as the
// offer document above — templates/monthly-report-template.docx has 5 tables
// with {{TOKEN}} markers (see the chat that built this for the full field
// mapping). Table 0 is the KPI summary row (5 tokens, filled once, no
// cloning); tables 1-4 each have a single template row that gets cloned once
// per matching record, or left as one blank row when a section has none.
const MONTHLY_REPORT_TEMPLATE_PATH = path.join(__dirname, 'templates', 'monthly-report-template.docx');
let monthlyReportTemplateEntriesCache = null;
function loadMonthlyReportTemplateEntries() {
  if (!monthlyReportTemplateEntriesCache) {
    if (!fs.existsSync(MONTHLY_REPORT_TEMPLATE_PATH)) throw new Error('قالب التقرير الشهري غير موجود على السيرفر (templates/monthly-report-template.docx)');
    monthlyReportTemplateEntriesCache = unzip(fs.readFileSync(MONTHLY_REPORT_TEMPLATE_PATH));
  }
  return monthlyReportTemplateEntriesCache;
}
// "2026-08-20" -> "20 / 08 / 2026" — same date shape the offer template uses.
function formatReportDate(iso) {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(iso || '');
  return m ? `${m[3]} / ${m[2]} / ${m[1]}` : '';
}
// "بيان الاصناف" — every item name joined into one line, falling back to the
// legacy single-item fields for records saved before the items[] array existed.
function itemsStatement(rec) {
  const names = (rec.items || []).map(it => it.item).filter(Boolean);
  if (names.length) return names.join('، ');
  return rec.item || '';
}
// Finds the <w:tr>...</w:tr> that contains anchorToken (unique to one
// table's template row) and replaces it with one cloned+filled row per entry
// in rowsData — same idea as buildItemRowXml above, generalized to N named
// tokens instead of ITEM/QUANTITY/UNIT_PRICE/TOTAL specifically. Rows are
// found via regex scan (not a plain lastIndexOf('<w:tr>')) because this
// template's rows carry attributes (<w:tr w:rsidR="...">), unlike the offer
// template's bare <w:tr>.
function cloneTemplateRow(xml, anchorToken, rowsData) {
  const rowRe = /<w:tr[ >][\s\S]*?<\/w:tr>/g;
  let m, templateRow = null, rowStart = -1, rowEnd = -1;
  while ((m = rowRe.exec(xml))) {
    if (m[0].includes(anchorToken)) { templateRow = m[0]; rowStart = m.index; rowEnd = m.index + m[0].length; break; }
  }
  if (templateRow === null) throw new Error('قالب التقرير الشهري غير متوافق: لم يتم العثور على صف ' + anchorToken);
  const clonedRows = rowsData.map(tokens => {
    let row = templateRow;
    for (const [token, value] of Object.entries(tokens)) row = row.split(token).join(escapeXml(value));
    return row;
  }).join('');
  return xml.slice(0, rowStart) + clonedRows + xml.slice(rowEnd);
}
function buildMonthlyReportDocx({ periodFrom, periodTo, branchTitle, kpis, section1, section2, section3, section4 }) {
  const entries = loadMonthlyReportTemplateEntries();
  let xml = entries.get('word/document.xml').toString('utf-8');

  const headerValues = {
    '{{REPORT_DATE}}': formatReportDate(todayISO()),
    '{{PERIOD_FROM}}': formatReportDate(periodFrom),
    '{{PERIOD_TO}}': formatReportDate(periodTo),
    '{{BRANCH_TITLE}}': branchTitle
  };
  for (const [token, value] of Object.entries(headerValues)) xml = xml.split(token).join(escapeXml(value));

  const kpiValues = {
    '{{KPI_HIGH_PRIORITY}}': String(kpis.highPriority),
    '{{KPI_PO_COUNT}}': String(kpis.poCount),
    '{{KPI_PENDING_OR_DECLINE}}': String(kpis.pendingOrDecline),
    '{{KPI_SENT_TO_CUSTOMER}}': String(kpis.sentToCustomer),
    '{{KPI_TOTAL_QUOTES}}': String(kpis.totalQuotes)
  };
  for (const [token, value] of Object.entries(kpiValues)) xml = xml.split(token).join(escapeXml(value));

  const blank = (keys) => [Object.fromEntries(keys.map(k => [k, '']))];

  // أولا / العروض المتوقع صدور أوامر توريد لها
  const s1Keys = ['{{SERIAL}}', '{{COMPANY}}', '{{ITEMS}}', '{{VALUE}}', '{{CUSTOMER_RESPONSE}}', '{{ACTION_TAKEN}}'];
  xml = cloneTemplateRow(xml, '{{ACTION_TAKEN}}', section1.length ? section1.map((r, i) => ({
    '{{SERIAL}}': String(i + 1), '{{COMPANY}}': r.company, '{{ITEMS}}': r.items,
    '{{VALUE}}': r.value, '{{CUSTOMER_RESPONSE}}': r.customerResponse, '{{ACTION_TAKEN}}': r.actionTaken
  })) : blank(s1Keys));

  // ثانيا / أوامر التوريد PO
  const s2Keys = ['{{SERIAL}}', '{{COMPANY}}', '{{ITEMS}}', '{{VALUE}}', '{{SUPPLY_TYPE}}', '{{CURRENT_STATUS}}'];
  xml = cloneTemplateRow(xml, '{{CURRENT_STATUS}}', section2.length ? section2.map((r, i) => ({
    '{{SERIAL}}': String(i + 1), '{{COMPANY}}': r.company, '{{ITEMS}}': r.items,
    '{{VALUE}}': r.value, '{{SUPPLY_TYPE}}': r.supplyType, '{{CURRENT_STATUS}}': r.currentStatus
  })) : blank(s2Keys));

  // ثالثا / كل العروض السعرية
  const s3Keys = ['{{SERIAL}}', '{{COMPANY}}', '{{ITEMS}}', '{{VALUE}}', '{{QUOTE_DATE}}'];
  xml = cloneTemplateRow(xml, '{{QUOTE_DATE}}', section3.length ? section3.map((r, i) => ({
    '{{SERIAL}}': String(i + 1), '{{COMPANY}}': r.company, '{{ITEMS}}': r.items,
    '{{VALUE}}': r.value, '{{QUOTE_DATE}}': r.quoteDate
  })) : blank(s3Keys));

  // رابعا / طلبات مازالت تحت التسعير
  const s4Keys = ['{{SERIAL}}', '{{COMPANY}}', '{{ITEMS}}', '{{REQUEST_DATE}}', '{{NOTES}}'];
  xml = cloneTemplateRow(xml, '{{REQUEST_DATE}}', section4.length ? section4.map((r, i) => ({
    '{{SERIAL}}': String(i + 1), '{{COMPANY}}': r.company, '{{ITEMS}}': r.items,
    '{{REQUEST_DATE}}': r.requestDate, '{{NOTES}}': r.notes
  })) : blank(s4Keys));

  const outEntries = [];
  for (const [name, data] of entries) {
    outEntries.push({ name, data: name === 'word/document.xml' ? Buffer.from(xml, 'utf-8') : data });
  }
  return zip(outEntries);
}

// ================= Auth routes =================
// Per-account lockout, independent of the per-IP loginLimiter above. The IP
// limiter alone can be bypassed by spreading attempts across many IPs
// (botnets, proxies) — this catches that by tracking failures per *username*
// regardless of which IP they came from. 8 failed attempts locks that account
// out for 15 minutes; any successful login clears it.
const failedLoginAttempts = {}; // username -> { count, lockedUntil }
const MAX_FAILED_ATTEMPTS = 8;
const LOCKOUT_MS = 15 * 60 * 1000;
setInterval(() => {
  const now = Date.now();
  for (const name of Object.keys(failedLoginAttempts)) {
    const rec = failedLoginAttempts[name];
    if ((!rec.lockedUntil || rec.lockedUntil < now) && rec.count === 0) delete failedLoginAttempts[name];
  }
}, 30 * 60 * 1000).unref();

app.post('/api/login', loginLimiter, (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'من فضلك أدخل اسم المستخدم وكلمة المرور' });
  }

  const lock = failedLoginAttempts[username];
  if (lock && lock.lockedUntil && lock.lockedUntil > Date.now()) {
    return res.status(429).json({ error: 'الحساب متوقف مؤقتاً بسبب محاولات دخول فاشلة كثيرة، حاول تاني بعد شوية' });
  }

  const users = readUsers();
  const u = users.users.find(x => x.username === username);
  // Always run a scrypt hash even on unknown usernames, so the response time
  // doesn't leak whether the username exists (basic timing-attack mitigation).
  const decoy = { salt: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', hash: '00'.repeat(64) };
  const target = u || decoy;
  const ok = u && verifyPassword(password, target.salt, target.hash);
  if (!ok) {
    const rec = failedLoginAttempts[username] || { count: 0, lockedUntil: 0 };
    rec.count += 1;
    if (rec.count >= MAX_FAILED_ATTEMPTS) { rec.lockedUntil = Date.now() + LOCKOUT_MS; rec.count = 0; }
    failedLoginAttempts[username] = rec;
    return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
  }
  delete failedLoginAttempts[username];
  const token = crypto.randomBytes(32).toString('hex');
  const user = publicUser(u);
  sessions[token] = { user, expiresAt: Date.now() + SESSION_TTL_MS };
  logActivity(user, 'تسجيل دخول', 'نظام', '', '');
  res.json({ token, user });
});

// Live-update stream (see the "Live updates" section above). Placed BEFORE
// the blanket requireAuth below because EventSource — the browser API for
// this — cannot send an Authorization header, so the session token arrives
// as a query parameter here instead; this route checks it itself the same
// way requireAuth does everywhere else, just reading it from a different place.
app.get('/api/events', (req, res) => {
  const token = typeof req.query.token === 'string' ? req.query.token : null;
  const session = token && sessions[token];
  if (!session || session.expiresAt < Date.now()) return res.status(401).end();
  session.expiresAt = Date.now() + SESSION_TTL_MS; // same sliding expiry as any other request

  res.set({
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no' // if this ever sits behind an nginx/reverse proxy, tells it not to buffer the stream
  });
  res.flushHeaders();
  res.write(': connected\n\n');
  sseClients.add(res);

  // Keeps the connection alive through proxies/load balancers that close
  // idle connections after a short timeout.
  const heartbeat = setInterval(() => { try { res.write(': ping\n\n'); } catch (e) { /* ignore */ } }, 25000);
  heartbeat.unref();

  req.on('close', () => { clearInterval(heartbeat); sseClients.delete(res); });
});

app.use('/api', requireAuth); // everything below requires login

app.post('/api/logout', (req, res) => {
  logActivity(req.user, 'تسجيل خروج', 'نظام', '', '');
  delete sessions[req.token];
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => res.json({ user: req.user }));

// ================= Records API =================
app.get('/api/records', (req, res) => {
  const data = readData();
  // Every user only ever sees the records belonging to their own branch
  // (ACH/AXH/SP) — admins see across all branches. This single scope point
  // covers the "requests" / "followup" / "quotes" tabs at once since they're
  // all rendered client-side from this same list.
  res.json({ ...data, records: scopeRecords(req.user, data.records) });
});

// ================= Overview report (Excel with real embedded charts) =================
// Mirrors the Home page's own client-side stats (see periodStats/avgDaysBetween/
// monthlyTrend in public/index.html) but recomputes them here so the export can
// carry native Excel charts — the bundled SheetJS build the rest of the app's
// exports use can only write plain cell data, not chart objects, so this one
// export goes through xlsx-chart instead, which generates real chart parts.
app.get('/api/reports/overview.xlsx', requirePermission('export_reports'), (req, res) => {
  try {
    const data = readData();
    const records = scopeRecords(req.user, data.records);
    const ar = req.query.lang !== 'en';
    // localISODate/localISOMonth (shared with the browser — see
    // public/js/dateUtils.js) read LOCAL calendar fields instead of going
    // through toISOString() (which converts to UTC first). For a server
    // running east of UTC (e.g. Cairo, UTC+2/+3), building "the 1st of this
    // month" locally and then calling toISOString() rolled it back to the
    // last day of the PREVIOUS month — silently dropping the current month
    // from the default report period and from the trend chart below.
    const now = new Date();
    const defaultFrom = localISODate(new Date(now.getFullYear(), now.getMonth(), 1));
    const defaultTo = localISODate(new Date(now.getFullYear(), now.getMonth() + 1, 0));
    const dateRe = /^\d{4}-\d{2}-\d{2}$/;
    const from = dateRe.test(req.query.from || '') ? req.query.from : defaultFrom;
    const to = dateRe.test(req.query.to || '') ? req.query.to : defaultTo;
    const compare = req.query.compare === '1';
    const isSuper = req.user.role === 'super_admin';

    function periodStats(recs, f, t) {
      const inPeriod = recs.filter(r => r.dateCreated >= f && r.dateCreated <= t);
      const won = inPeriod.filter(r => r.quoteStatus === 'po').length;
      const declined = inPeriod.filter(r => r.quoteStatus === 'decline').length;
      const lost = inPeriod.filter(r => r.quoteStatus === 'loss').length;
      const quoted = inPeriod.filter(r => r.stage === 'quote').length;
      const convRate = quoted ? Math.round((won / quoted) * 100) : 0;
      return { records: inPeriod, count: inPeriod.length, won, declined, lost, quoted, convRate };
    }
    function priorPeriodRange(f, t) {
      const fromD = new Date(f), toD = new Date(t);
      const days = Math.round((toD - fromD) / 86400000) + 1;
      const prevTo = new Date(fromD); prevTo.setDate(prevTo.getDate() - 1);
      const prevFrom = new Date(prevTo); prevFrom.setDate(prevFrom.getDate() - (days - 1));
      return { from: localISODate(prevFrom), to: localISODate(prevTo) };
    }
    function avgDaysBetween(recs, startField, endField) {
      const diffs = recs.filter(r => r[startField] && r[endField])
        .map(r => (new Date(r[endField]) - new Date(r[startField])) / 86400000)
        .filter(d => isFinite(d) && d >= 0);
      if (!diffs.length) return { avg: null, count: 0 };
      return { avg: Math.round((diffs.reduce((s, d) => s + d, 0) / diffs.length) * 10) / 10, count: diffs.length };
    }
    function wonMonthKey(r) {
      if (r.quoteStatus !== 'po') return '';
      return r.wonAt || r.quoteDate || r.dateCreated || '';
    }
    function monthlyTrend(recs, monthsBack) {
      const months = [];
      for (let i = monthsBack - 1; i >= 0; i--) {
        months.push(localISOMonth(new Date(now.getFullYear(), now.getMonth() - i, 1)));
      }
      return months.map(m => ({
        month: m,
        requests: recs.filter(r => r.dateCreated && r.dateCreated.startsWith(m)).length,
        won: recs.filter(r => wonMonthKey(r).startsWith(m)).length
      }));
    }

    const stats = periodStats(records, from, to);
    const toQuote = avgDaysBetween(stats.records, 'dateCreated', 'quoteDate');
    const toWin = avgDaysBetween(stats.records, 'dateCreated', 'wonAt');
    const trend = monthlyTrend(records, 12);

    // xlsx-chart's convention: `titles` become the chart's SERIES, `fields`
    // become the x-axis CATEGORIES — i.e. data[title][field] = value.
    const L = {
      requests: ar ? 'طلبات' : 'Requests', won: ar ? 'فوز (PO)' : 'Won (PO)',
      count: ar ? 'العدد' : 'Count', periodRequests: ar ? 'طلبات الفترة' : 'Period Requests',
      declined: ar ? 'اعتذار' : 'Declined', lost: ar ? 'خسارة' : 'Lost',
      avgDays: ar ? 'متوسط الأيام' : 'Avg Days', toQuoteLabel: ar ? 'من الطلب للتسعير' : 'Request to Quote',
      toWinLabel: ar ? 'من الطلب للفوز' : 'Request to Win', current: ar ? 'الفترة الحالية' : 'Current Period',
      previous: ar ? 'الفترة السابقة' : 'Previous Period', engineer: ar ? 'الطلبات' : 'Requests'
    };

    const charts = [];

    charts.push({
      chart: 'column',
      chartTitle: ar ? 'اتجاه الطلبات والفوز خلال آخر 12 شهر' : 'Requests & Wins Trend (Last 12 Months)',
      titles: [L.requests, L.won],
      fields: trend.map(d => d.month),
      data: {
        [L.requests]: Object.fromEntries(trend.map(d => [d.month, d.requests])),
        [L.won]: Object.fromEntries(trend.map(d => [d.month, d.won]))
      }
    });

    charts.push({
      chart: 'bar',
      chartTitle: ar ? `نتائج طلبات الفترة (${from} إلى ${to})` : `Period Outcomes (${from} to ${to})`,
      titles: [L.count],
      fields: [L.periodRequests, L.won, L.declined, L.lost],
      data: { [L.count]: { [L.periodRequests]: stats.count, [L.won]: stats.won, [L.declined]: stats.declined, [L.lost]: stats.lost } }
    });

    if (compare) {
      const prev = priorPeriodRange(from, to);
      const prevStats = periodStats(records, prev.from, prev.to);
      charts.push({
        chart: 'bar',
        chartTitle: ar ? `مقارنة بالفترة السابقة (${prev.from} إلى ${prev.to})` : `Compared to Previous Period (${prev.from} to ${prev.to})`,
        titles: [L.current, L.previous],
        fields: [L.periodRequests, L.won, L.declined, L.lost],
        data: {
          [L.current]: { [L.periodRequests]: stats.count, [L.won]: stats.won, [L.declined]: stats.declined, [L.lost]: stats.lost },
          [L.previous]: { [L.periodRequests]: prevStats.count, [L.won]: prevStats.won, [L.declined]: prevStats.declined, [L.lost]: prevStats.lost }
        }
      });
    }

    charts.push({
      chart: 'bar',
      chartTitle: ar ? 'متوسط زمن الاستجابة (يوم)' : 'Average Response Time (days)',
      titles: [L.avgDays],
      fields: [L.toQuoteLabel, L.toWinLabel],
      data: { [L.avgDays]: { [L.toQuoteLabel]: toQuote.avg || 0, [L.toWinLabel]: toWin.avg || 0 } }
    });

    const engNames = [...new Set(stats.records.map(r => (r.salesEngineer || '').trim()).filter(Boolean))].sort((a, b) => a.localeCompare(b, 'ar'));
    if (engNames.length) {
      const reqByEng = {}, wonByEng = {};
      engNames.forEach(name => {
        const recs = stats.records.filter(r => (r.salesEngineer || '').trim() === name);
        reqByEng[name] = recs.length;
        wonByEng[name] = recs.filter(r => r.quoteStatus === 'po').length;
      });
      charts.push({
        chart: 'bar',
        chartTitle: ar ? 'الأداء حسب مهندس البيع (طلبات الفترة)' : 'Performance by Sales Engineer (Period)',
        titles: [L.requests, L.won],
        fields: engNames,
        data: { [L.requests]: reqByEng, [L.won]: wonByEng }
      });
    }

    if (isSuper) {
      const reqByBranch = {}, wonByBranch = {};
      BRANCH_CODES.forEach(bc => {
        const recs = stats.records.filter(r => recordBranch(r) === bc);
        reqByBranch[bc] = recs.length;
        wonByBranch[bc] = recs.filter(r => r.quoteStatus === 'po').length;
      });
      charts.push({
        chart: 'bar',
        chartTitle: ar ? 'الأداء حسب الفرع (طلبات الفترة)' : 'Performance by Branch (Period)',
        titles: [L.requests, L.won],
        fields: BRANCH_CODES,
        data: { [L.requests]: reqByBranch, [L.won]: wonByBranch }
      });
    }

    const xlsxChart = new XLSXChart();
    xlsxChart.generate({ charts }, (err, buf) => {
      if (err) {
        console.error('overview report generation failed:', err);
        return res.status(500).json({ error: 'تعذر إنشاء ملف التقرير' });
      }
      const filename = ar ? 'نظرة عامة.xlsx' : 'overview.xlsx';
      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      res.setHeader('Content-Disposition', `attachment; filename="overview.xlsx"; filename*=UTF-8''${encodeURIComponent(filename)}`);
      res.send(buf);
    });
  } catch (e) {
    console.error('overview report failed:', e);
    res.status(500).json({ error: 'تعذر إنشاء ملف التقرير' });
  }
});

const ORDER_TYPES = ['طلب سعر عادي', 'مناقصة', 'طلب يوم محدد'];
const PRIORITY_LEVELS = ['عالي', 'متوسط', 'ضعيف'];
const PO_SUPPLY_TYPES = ['بضاعة حاضرة', 'استيراد'];
const ALLOWED_STAGES = ['request', 'followup', 'quote', 'closed'];
const FOLLOWUP_STATUSES = ['تحت التسعير', 'تحت الدراسة الفنية', 'بانتظار موافقة داخلية', 'بانتظار رد العميل', 'تم إرسال العرض المبدئي', 'إغلاق'];
// Only these fields may ever be changed through PATCH /api/records/:id — this stops
// a caller from injecting unexpected keys (e.g. "id", "code") into a record.
// 'items' (the array of بنود) is validated/sanitized separately below instead
// of through this generic string-clamping loop, since it isn't a plain string.
const PATCHABLE_FIELDS = [
  'customer', 'company', 'phone', 'email', 'orderType', 'requiredDate',
  'salesEngineer', 'techOfficeEngineer', 'priority', 'notes', 'stage', 'followupStatus', 'followupNotes',
  'codeArrivalDate',
  'quoteValidity', 'quoteNotes', 'quoteStatus', 'poNumber', 'declineReason', 'lossReason', 'inqNo',
  'closeReason', 'sentToCustomer', 'customerResponse', 'actionTaken', 'poSupplyType', 'poCurrentStatus'
];
// Simple string length caps so nobody can store megabyte-sized field values.
const MAX_LEN = { customer: 200, company: 200, phone: 40, email: 200, item: 300, description: 2000, brand: 150, salesEngineer: 150, techOfficeEngineer: 150, notes: 2000, followupNotes: 2000, quoteNotes: 2000, poNumber: 100, declineReason: 1000, lossReason: 1000, inqNo: 100, itemNotes: 1000, closeReason: 1000, chatMessage: 2000, recordLabel: 300, customerResponse: 2000, actionTaken: 2000, poCurrentStatus: 2000 };
// The only tracking colors an item can be tagged with — anything else sent
// from the client is dropped rather than stored.
const ITEM_COLOR_TAGS = ['brown', 'blue', 'gray', 'purple'];
function clampStr(v, max) { return typeof v === 'string' ? v.slice(0, max) : v; }

// Validates/cleans a raw `items` array coming from the client: keeps only
// entries that have a non-empty بند name, clamps text lengths, and always
// (re)computes each item's total itself as quantity × unitPrice — the client
// only ever sends quantity/unitPrice for pricing, never a trusted total.
// The "priced" checkbox is the actual gate for registering a price: unless
// it's checked, whatever quantity/unit price was typed is discarded rather
// than saved — this is enforced here (not just in the UI) so it holds no
// matter which screen the save came from.
function sanitizeItems(rawItems) {
  if (!Array.isArray(rawItems)) return null;
  return rawItems.map(it => {
    const item = clampStr(String((it && it.item) || ''), MAX_LEN.item).trim();
    const description = clampStr(String((it && it.description) || ''), MAX_LEN.description);
    const brand = clampStr(String((it && it.brand) || ''), MAX_LEN.brand);
    const priced = !!(it && it.priced);
    const qtyNum = parseFloat(it && it.quantity);
    const priceNum = parseFloat(it && it.unitPrice);
    const quantity = (priced && it && it.quantity !== undefined && it.quantity !== '' && isFinite(qtyNum)) ? qtyNum : '';
    const unitPrice = (priced && it && it.unitPrice !== undefined && it.unitPrice !== '' && isFinite(priceNum)) ? priceNum : '';
    const total = (quantity !== '' && unitPrice !== '') ? Math.round(quantity * unitPrice * 100) / 100 : '';
    const colorTag = ITEM_COLOR_TAGS.includes(it && it.colorTag) ? it.colorTag : '';
    const itemNotes = clampStr(String((it && it.itemNotes) || ''), MAX_LEN.itemNotes);
    // Per-بند tracking (independent of every other بند in the same request):
    // its own متابعة status and its own "تاريخ وصول الكود من المكتب الفني".
    const followupStatus = FOLLOWUP_STATUSES.includes(it && it.followupStatus) ? it.followupStatus : 'تحت التسعير';
    const codeArrivalDate = isValidISODate(it && it.codeArrivalDate) ? it.codeArrivalDate : '';
    return { item, description, brand, quantity, unitPrice, total, priced, colorTag, itemNotes, followupStatus, codeArrivalDate };
  }).filter(it => it.item);
}
// Short "البند + كام بند تاني" text used in activity-log lines.
function itemsLogSummary(rec) {
  const items = rec.items || [];
  if (!items.length) return '';
  return items.length === 1 ? items[0].item : `${items[0].item} (+${items.length - 1} بند آخر)`;
}

// ================= Field-level change tracking =================
// See lib/auditDiff.js (and test/auditDiff.test.js) — extracted out of this
// file so the diff logic can be unit-tested without spinning up Express.

app.post('/api/records', requirePermission('create_request'), (req, res) => {
  const data = readData();
  const body = req.body || {};
  const items = sanitizeItems(body.items) || [];
  if (!body.customer || items.length === 0) {
    return res.status(400).json({ error: 'اسم العميل وبند واحد على الأقل مطلوبان' });
  }
  // Branch admins & viewers-turned-editors always code under their own fixed
  // branch. The super admin isn't tied to one branch, so they must explicitly
  // choose which branch's numbering this new request should use.
  let branchCode = req.user.branchCode;
  if (req.user.role === 'super_admin') {
    if (!body.branchCode || !BRANCH_CODES.includes(body.branchCode)) {
      return res.status(400).json({ error: 'اختر الفرع المطلوب تكويد الطلب تحته' });
    }
    branchCode = body.branchCode;
  }
  const orderType = ORDER_TYPES.includes(body.orderType) ? body.orderType : ORDER_TYPES[0];
  const rec = {
    id: 'r' + Date.now() + Math.floor(Math.random() * 1000),
    code: genCode(data, branchCode),
    branchCode: branchCode,
    customer: clampStr(String(body.customer), MAX_LEN.customer),
    company: clampStr(String(body.company || ''), MAX_LEN.company),
    phone: clampStr(String(body.phone || ''), MAX_LEN.phone),
    email: clampStr(String(body.email || ''), MAX_LEN.email),
    // A new request never has pricing yet — strip any quantity/unitPrice/total
    // the client might have sent and keep only the بند/الوصف/الماركة per item.
    items: items.map(it => ({ item: it.item, description: it.description, brand: it.brand, quantity: '', unitPrice: '', total: '', priced: false, colorTag: '', itemNotes: '', followupStatus: 'تحت التسعير', codeArrivalDate: '' })),
    orderType,
    // Both "طلب يوم محدد" (fixed-date) and "مناقصة" (tender) requests carry a
    // deadline — used by the "تنبيهات الطلبات والعروض" alerts page to warn
    // before it arrives. A plain "طلب سعر عادي" has no deadline concept.
    requiredDate: (orderType === 'طلب يوم محدد' || orderType === 'مناقصة') ? (body.requiredDate || '') : '',
    salesEngineer: body.salesEngineer || '',
    techOfficeEngineer: body.techOfficeEngineer || '',
    priority: PRIORITY_LEVELS.includes(body.priority) ? body.priority : 'متوسط',
    notes: body.notes || '',
    dateCreated: todayISO(),
    stage: 'request',
    followupStatus: 'تحت التسعير',
    followupNotes: '',
    codeArrivalDate: '',
    offerCode: '',
    quoteDate: '',
    quoteValue: '', quoteValidity: '', quoteNotes: '',
    quoteStatus: 'pending', poNumber: '', poSupplyType: '', declineReason: '', lossReason: '', inqNo: '',
    productImages: [],
    sampleImages: [],
    sentToCustomer: false,
    customerResponse: '',
    actionTaken: '',
    poCurrentStatus: '',
    closedAt: '', closedBy: '', closeReason: '', wonAt: ''
  };
  data.records.push(rec);
  writeData(data);
  logActivity(req.user, 'إنشاء طلب سعر جديد', 'طلب', rec.code, `${rec.customer} | ${itemsLogSummary(rec)}`);
  res.status(201).json(rec);
});

// Every distinct kind of edit /api/records/:id handles maps to its own
// permission (see public/js/permissions.js) — the client always says which
// one it's doing via the `_action` field, and that's what gets checked here,
// rather than guessing the action from the shape of the patch. Guessing from
// shape would mean a client could dodge a permission check just by sending
// an unusual field combination; requiring a known, whitelisted action name
// closes that off.
const PATCH_ACTIONS = new Set([
  'move_to_followup', 'price_items', 'update_followup_status', 'close_followup',
  'convert_to_quote', 'register_po', 'register_decline', 'register_loss',
  'revert_quote_status', 'edit_request', 'update_sent_to_customer', 'update_quote_response'
]);
app.patch('/api/records/:id', (req, res) => {
  const data = readData();
  const rec = data.records.find(r => r.id === req.params.id);
  if (!rec) return res.status(404).json({ error: 'السجل غير موجود' });
  // A branch admin (or viewer) can never touch a record outside their own
  // branch, even by guessing its id directly — this is what actually enforces
  // the branch isolation (the UI filtering alone wouldn't stop a direct API
  // call). The super admin is exempt: they're allowed to reach any branch.
  if (req.user.role !== 'super_admin' && recordBranch(rec) !== req.user.branchCode) {
    return res.status(403).json({ error: 'لا تملك صلاحية الوصول لهذا الطلب' });
  }

  const rawPatch = req.body || {};
  if (!PATCH_ACTIONS.has(rawPatch._action)) {
    return res.status(400).json({ error: 'إجراء غير معروف' });
  }
  if (!hasPermission(req.user, rawPatch._action)) {
    return res.status(403).json({ error: 'لا تملك صلاحية القيام بهذا الإجراء' });
  }
  if (rawPatch.stage !== undefined && !ALLOWED_STAGES.includes(rawPatch.stage)) {
    return res.status(400).json({ error: 'مرحلة غير معروفة' });
  }
  if (rawPatch.followupStatus !== undefined && !FOLLOWUP_STATUSES.includes(rawPatch.followupStatus)) {
    return res.status(400).json({ error: 'حالة متابعة غير معروفة' });
  }
  if (rawPatch.quoteStatus !== undefined && !['pending', 'po', 'decline', 'loss'].includes(rawPatch.quoteStatus)) {
    return res.status(400).json({ error: 'حالة عرض سعر غير معروفة' });
  }
  // orderType is a fixed list too (same as at creation time) — validate it here
  // as well, otherwise an edit could silently drift a record to a value the UI
  // and the offer-document builder don't know how to handle.
  if (rawPatch.orderType !== undefined && !ORDER_TYPES.includes(rawPatch.orderType)) {
    return res.status(400).json({ error: 'نوع طلب غير معروف' });
  }
  // priority is a fixed list too (same as at creation time) — validate it here as well.
  if (rawPatch.priority !== undefined && !PRIORITY_LEVELS.includes(rawPatch.priority)) {
    return res.status(400).json({ error: 'أولوية غير معروفة' });
  }
  // sentToCustomer is a plain boolean flag — coerce anything sent to a real boolean
  // rather than storing whatever truthy/falsy value the client happened to send.
  if (rawPatch.sentToCustomer !== undefined) {
    rawPatch.sentToCustomer = !!rawPatch.sentToCustomer;
  }
  // Registering a PO requires BOTH the PO number and the supply type (بضاعة
  // حاضرة / استيراد) — enforced here too, not just in the UI, so a direct API
  // call can never register a "win" with either one missing.
  if (rawPatch._action === 'register_po') {
    if (!rawPatch.poNumber || !String(rawPatch.poNumber).trim()) {
      return res.status(400).json({ error: 'رقم أمر الشراء مطلوب' });
    }
    if (!PO_SUPPLY_TYPES.includes(rawPatch.poSupplyType)) {
      return res.status(400).json({ error: 'نوع التوريد (بضاعة حاضرة / استيراد) مطلوب' });
    }
  }

  // Only allow whitelisted fields through, and clamp string lengths — prevents
  // callers from injecting arbitrary keys or oversized values into the record.
  const patch = {};
  for (const key of Object.keys(rawPatch)) {
    if (!PATCHABLE_FIELDS.includes(key)) continue;
    const val = rawPatch[key];
    patch[key] = (typeof val === 'string' && MAX_LEN[key]) ? clampStr(val, MAX_LEN[key]) : val;
  }
  // `items` (the بنود array) is validated separately, and quoteValue is always
  // recomputed from it server-side — never taken as-is from the client — so a
  // request/quote's total can never drift from the sum of its item totals.
  if (rawPatch.items !== undefined) {
    const items = sanitizeItems(rawPatch.items);
    if (!items || items.length === 0) {
      return res.status(400).json({ error: 'أضف بند واحد على الأقل' });
    }
    patch.items = items;
    patch.quoteValue = items.reduce((s, it) => s + (parseFloat(it.total) || 0), 0);
  }

  const before = { ...rec };
  Object.assign(rec, patch);

  // assign the next sequential offer code (Offer1, Offer2, ...) the moment a request
  // moves from "متابعة الطلبات" into "عروض الأسعار"
  if (patch.stage === 'quote' && before.stage === 'followup' && !rec.offerCode) {
    rec.offerCode = genOfferCode(data, recordBranch(rec));
    // Stamp the date the price quote was actually made — this is what the
    // "عروض الأسعار" table shows as "تاريخ عمل عرض السعر", separate from
    // dateCreated (تاريخ طلب السعر) and codeArrivalDate (تاريخ وصول الكود من المكتب الفني).
    rec.quoteDate = todayISO();
  }
  // Stamp the date a quote actually became a win — lets reports compute a real
  // "average time from request to win" instead of approximating with the quote
  // date. Cleared if the outcome is later switched away from PO (e.g. fixed a
  // mistaken entry), same spirit as closedAt/closedBy above.
  if (patch.quoteStatus === 'po' && before.quoteStatus !== 'po') {
    rec.wonAt = todayISO();
  } else if (patch.quoteStatus !== undefined && patch.quoteStatus !== 'po' && before.quoteStatus === 'po') {
    rec.wonAt = '';
  }
  // closing a followup request: stamp the closing date and keep it out of the
  // active follow-up list from now on — its data stays visible in "العملاء"
  // because /api/customers aggregates over every record regardless of stage.
  if (patch.stage === 'closed' && before.stage !== 'closed') {
    rec.closedAt = todayISO();
    rec.closedBy = req.user.name;
  }
  // Reopening a closed request (e.g. the item became available again) sends
  // it back to "متابعة الطلبات" and clears the closing stamp, since it's no
  // longer closed.
  if (patch.stage === 'followup' && before.stage === 'closed') {
    rec.closedAt = '';
    rec.closedBy = '';
    rec.closeReason = '';
  }
  writeData(data);

  // build a human-readable log line describing what changed
  let action = 'تعديل بيانات';
  if (patch.stage === 'followup' && before.stage === 'request') action = 'ترحيل الطلب إلى المتابعة';
  else if (patch.stage === 'followup' && before.stage === 'closed') action = 'إرجاع الطلب المغلق لقائمة المتابعة';
  else if (patch.stage === 'quote' && before.stage === 'followup') action = 'تحويل الطلب إلى عرض سعر (' + rec.offerCode + ')';
  else if (patch.stage === 'closed' && before.stage !== 'closed') action = 'إغلاق الطلب وتحويله لبيانات العميل';
  else if (patch.quoteStatus === 'po') action = 'تحويل العرض إلى أمر شراء (PO)';
  else if (patch.quoteStatus === 'decline') action = 'اعتذار عن العرض';
  else if (patch.quoteStatus === 'loss') action = 'تسجيل خسارة العرض';
  else if (patch.followupStatus) action = 'تحديث حالة المتابعة إلى: ' + patch.followupStatus;
  else if ('followupNotes' in patch) action = 'تحديث ملاحظات المتابعة';
  else if ('codeArrivalDate' in patch) action = 'تحديث تاريخ وصول الكود من المكتب الفني';
  else if (Object.keys(patch).some(k => ['customer','company','phone','email','items','orderType','requiredDate','salesEngineer','techOfficeEngineer','quoteValidity','quoteNotes'].includes(k))) action = 'تعديل بيانات العرض';

  logActivity(req.user, action, 'طلب', rec.code, buildEditDetails(rec.customer, before, patch));
  res.json(rec);
});

// Quick, independent update of one بند's own متابعة fields (status / تاريخ
// وصول الكود من المكتب الفني / ملاحظات) — this is what lets "متابعة الطلبات"
// track each item in a request on its own, so e.g. one already-priced بند
// doesn't drag the rest of the request's items along with it, and vice versa.
// Gated by the same permission as the request-level متابعة fields, since it's
// the same kind of edit just scoped to a single بند instead of the whole record.
app.patch('/api/records/:id/items/:idx', requirePermission('update_followup_status'), (req, res) => {
  const data = readData();
  const rec = data.records.find(r => r.id === req.params.id);
  if (!rec) return res.status(404).json({ error: 'السجل غير موجود' });
  if (req.user.role !== 'super_admin' && recordBranch(rec) !== req.user.branchCode) {
    return res.status(403).json({ error: 'لا تملك صلاحية الوصول لهذا الطلب' });
  }
  const idx = parseInt(req.params.idx, 10);
  const items = rec.items || [];
  if (!Number.isInteger(idx) || idx < 0 || idx >= items.length) {
    return res.status(404).json({ error: 'البند غير موجود' });
  }
  const body = req.body || {};
  const it = items[idx];
  const changes = [];
  if (body.followupStatus !== undefined) {
    if (!FOLLOWUP_STATUSES.includes(body.followupStatus)) return res.status(400).json({ error: 'حالة متابعة غير معروفة' });
    it.followupStatus = body.followupStatus;
    changes.push(`تحديث حالة متابعة البند "${it.item}" إلى: ${it.followupStatus}`);
  }
  if (body.codeArrivalDate !== undefined) {
    it.codeArrivalDate = isValidISODate(body.codeArrivalDate) ? body.codeArrivalDate : '';
    changes.push(`تحديث تاريخ وصول الكود من المكتب الفني للبند "${it.item}"`);
  }
  if (body.itemNotes !== undefined) {
    it.itemNotes = clampStr(String(body.itemNotes), MAX_LEN.itemNotes);
    changes.push(`تحديث ملاحظات متابعة البند "${it.item}"`);
  }
  if (!changes.length) return res.status(400).json({ error: 'لا يوجد تغيير' });
  writeData(data);
  logActivity(req.user, changes[0], 'طلب', rec.code, changes.join(' — '));
  res.json(rec);
});

// Deletion is grantable (delete_records) rather than hard-locked to
// super_admin, but a non-super-admin holding that permission still can't
// reach another branch's records — same branch-isolation rule as the PATCH
// route above. Only super_admin bypasses the branch check.
app.delete('/api/records/:id', requirePermission('delete_records'), (req, res) => {
  const data = readData();
  const rec = data.records.find(r => r.id === req.params.id);
  if (!rec) return res.status(404).json({ error: 'السجل غير موجود' });
  if (req.user.role !== 'super_admin' && recordBranch(rec) !== req.user.branchCode) {
    return res.status(403).json({ error: 'لا تملك صلاحية الوصول لهذا الطلب' });
  }

  data.records = data.records.filter(r => r.id !== req.params.id);
  writeData(data);
  // Clean up any saved offer-doc file that belonged to this record.
  try { if (fs.existsSync(offerDocPath(rec.id))) fs.unlinkSync(offerDocPath(rec.id)); } catch (e) { /* not critical */ }
  try { if (fs.existsSync(techOfferDocPath(rec.id))) fs.unlinkSync(techOfferDocPath(rec.id)); } catch (e) { /* not critical */ }
  // Clean up any saved product images that belonged to this record.
  try { const dir = productImagesDir(rec.id); if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true }); } catch (e) { /* not critical */ }
  try { const dir = sampleImagesDir(rec.id); if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true }); } catch (e) { /* not critical */ }

  // snapshot the deleted record inside the log so history survives the deletion
  logActivity(req.user, 'حذف سجل', 'طلب', rec.code, `العميل: ${rec.customer} | البند: ${itemsLogSummary(rec)} | كان في مرحلة: ${rec.stage}`);
  res.json({ ok: true });
});

// ================= Import from Excel ("استيراد SP") =================
// Bulk-loads historical SP/ACH/AXH records from the company's old Excel
// tracking sheet. Unlike a normal POST /api/records (which always mints a
// brand-new sequential code), an import must preserve each row's *existing*
// code/offer number exactly as it already appears in Excel — these requests
// were already coded by hand before this system existed. Restricted to the
// super admin since it can write directly into any branch and can inject
// codes that bypass the normal per-branch sequence, which is exactly the
// kind of system-level action the other super-admin-only routes are for.
//
// Column order this expects (matches the company's fixed Excel template,
// left to right; the sheet has two header rows — an English title row and
// an Arabic explanation row underneath it — both stripped client-side
// before this array of data rows is sent):
//  0 Branch (الفرع) | 1 Customer name (أسم العميل) | 2 phone/email (رقم تليفون العميل) |
//  3 code sent from reception (رقم طلب السعر — the SP/ACH/AXH number) | 4 INQ No |
//  5 kind of request (نوع الطلب) | 6 due date (صالح حتى => quoteValidity) |
//  7 date of give code (تاريخ الطلب => dateCreated) |
//  8 date sent from technical (تاريخ وصول الكود من المكتب الفني => codeArrivalDate) |
//  9 "Brand" column, actually البند => the item name itself |
//  10 "P.N + type" column, actually الوصف+الماركة => item description (kept as one combined field — the sheet doesn't split description from brand) |
//  11 date offer was sent (تاريخ العرض => quoteDate) |
//  12 "Loss Reason" column, actually الحالة الحالية لعرض السعر => the quote's current status/reason (see importQuoteStatus) |
//  13 feedback (ملاحظات عرض السعر => quoteNotes) | 14 Offer NO (رقم عرض السعر) | 15 Sales Manager (مهندس البيع)
const IMPORT_COLUMNS = 16;

// The Excel branch cell is free text typed by hand over the years, so this
// matches loosely rather than requiring an exact value. "chg" is included
// alongside "sp" because that is how the SP branch's cells are written in
// the company's sheet.
function importNormalizeBranch(raw) {
  const s = String(raw || '').trim().toLowerCase();
  if (!s) return null;
  if (s.includes('axh')) return 'AXH';
  if (s.includes('ach')) return 'ACH';
  if (s.includes('sp') || s.includes('chg')) return 'SP';
  return null;
}
// A row's own code (e.g. "SP184") already carries its branch as a prefix —
// used as a fallback whenever the Branch column itself is blank/unreadable.
function importBranchFromCode(code) {
  const m = /^([A-Za-z]+)\d+$/.exec(String(code || '').trim());
  return (m && BRANCH_CODES.includes(m[1].toUpperCase())) ? m[1].toUpperCase() : null;
}
// The Excel cell is sometimes just the bare number ("184") and sometimes the
// full code ("SP184") — normalize both into the full "<BRANCH><n>" form.
function importFullCode(raw, branchCode) {
  const s = String(raw || '').trim();
  if (!s) return '';
  if (/^\d+$/.test(s)) return branchCode + s;
  return s.toUpperCase().replace(/\s+/g, '');
}
function importFullOfferCode(raw, branchCode) {
  const s = String(raw || '').trim();
  if (!s) return '';
  if (/^\d+$/.test(s)) return branchCode + 'Offer' + s;
  return s.toUpperCase().replace(/\s+/g, '');
}
function importOrderType(raw) {
  const s = String(raw || '').trim().toLowerCase();
  if (!s) return ORDER_TYPES[0];
  if (s.includes('مناقص') || s.includes('tender')) return 'مناقصة';
  if (s.includes('محدد') || s.includes('specific') || s.includes('fixed')) return 'طلب يوم محدد';
  return ORDER_TYPES[0];
}
// Splits the single "phone or email" Excel column into the app's two
// separate fields, by whichever one it actually looks like.
function importPhoneOrEmail(raw) {
  const s = String(raw || '').trim();
  if (!s) return { phone: '', email: '' };
  return s.includes('@') ? { phone: '', email: s } : { phone: s, email: '' };
}
// Best-effort date parsing: accepts ISO ("2026-05-01"), day/month/year or
// month/day/year with '/', '-', '.' or spaces as separators, a bare Excel
// serial number (in case a date cell slips through unconverted), Arabic-Indic
// digits (٠-٩), and a handful of common month-name spellings. Any value that
// still doesn't match a recognized shape is left blank rather than guessed at
// — the date field just stays empty (and gets flagged as a warning by the
// caller) instead of silently showing something wrong.
const IMPORT_MONTHS = {
  jan:1, january:1, feb:2, february:2, mar:3, march:3, apr:4, april:4, may:5,
  jun:6, june:6, jul:7, july:7, aug:8, august:8, sep:9, sept:9, september:9,
  oct:10, october:10, nov:11, november:11, dec:12, december:12,
  يناير:1, فبراير:2, مارس:3, أبريل:4, ابريل:4, مايو:5, يونيو:6, يونية:6,
  يوليو:7, يولية:7, أغسطس:8, اغسطس:8, سبتمبر:9, أكتوبر:10, اكتوبر:10,
  نوفمبر:11, ديسمبر:12
};
function importDate(raw) {
  // Excel's own serial-date number (days since 1899-12-30), in case a cell
  // arrives as a raw number instead of the formatted string SheetJS usually
  // produces with raw:false.
  if (typeof raw === 'number' && isFinite(raw) && raw > 0) {
    const d = new Date(Math.round((raw - 25569) * 86400 * 1000));
    if (!isNaN(d.getTime())) return d.toISOString().slice(0, 10);
  }
  let s = String(raw == null ? '' : raw).trim();
  if (!s) return '';
  // Normalize Arabic-Indic / Extended Arabic-Indic digits to plain ASCII.
  s = s.replace(/[\u0660-\u0669\u06F0-\u06F9]/g, ch => String(ch.charCodeAt(0) & 0xf));
  const pad = n => String(n).padStart(2, '0');

  let m = /^(\d{4})[\/\-.\s](\d{1,2})[\/\-.\s](\d{1,2})/.exec(s);
  if (m) return `${m[1]}-${pad(m[2])}-${pad(m[3])}`;
  m = /^(\d{1,2})[\/\-.\s](\d{1,2})[\/\-.\s](\d{4})/.exec(s);
  if (m) return `${m[3]}-${pad(m[2])}-${pad(m[1])}`;

  // "1 May 2026" / "1 مايو 2026" / "May 1, 2026" — day and year as digits,
  // month spelled out in between.
  m = /^(\d{1,2})[\s\-]+([A-Za-z\u0600-\u06FF]+)[\s,\-]+(\d{4})/.exec(s);
  if (m && IMPORT_MONTHS[m[2].toLowerCase()]) return `${m[3]}-${pad(IMPORT_MONTHS[m[2].toLowerCase()])}-${pad(m[1])}`;
  m = /^([A-Za-z\u0600-\u06FF]+)[\s,\-]+(\d{1,2})[\s,\-]+(\d{4})/.exec(s);
  if (m && IMPORT_MONTHS[m[1].toLowerCase()]) return `${m[3]}-${pad(IMPORT_MONTHS[m[1].toLowerCase()])}-${pad(m[2])}`;

  // A bare number with no separators at all — most likely an Excel serial
  // date that came through as plain text (e.g. "45782").
  m = /^(\d{4,6})$/.exec(s);
  if (m) {
    const d = new Date(Math.round((parseInt(m[1], 10) - 25569) * 86400 * 1000));
    if (!isNaN(d.getTime()) && d.getFullYear() > 1990 && d.getFullYear() < 2100) return d.toISOString().slice(0, 10);
  }
  return '';
}
// Status comes strictly from this column ("Loss Reason" in the header, but
// the branch's own Arabic note underneath it says "الحالة الحالية لعرض
// السعر" — the quote's current status) — the "feedback" column next to it is
// never inspected for status; it only ever becomes the quote's notes:
//   - this column reads like a win/PO      -> po
//   - this column has any other text in it -> loss, using that text verbatim
//   - this column is empty                 -> pending (still awaiting a result)
// This is a best-effort default, not a guarantee — every imported record can
// still be corrected afterward from its normal PO / اعتذار / خسارة buttons.
const IMPORT_WIN_WORDS = ['po', 'أمر شراء', 'امر شراء', 'فوز', 'قبول', 'accepted', 'won', 'موافق', 'تم البيع'];
// If the branch wrote "إغلاق"/"اغلاق"/"close"/"closed" in the feedback
// column, the request itself should land straight in "الطلبات المغلقة"
// (closed stage) rather than sitting in followup/quote — this overrides the
// normal offerCode-based stage choice. Arabic alef variants (ا/أ/إ/آ) are
// normalized first so any common spelling of "إغلاق" matches.
function normalizeArabicAlef(s) { return s.replace(/[أإآ]/g, 'ا'); }
const IMPORT_CLOSE_WORDS = ['اغلاق', 'اغلق', 'مغلق', 'close', 'closed'];
function importFeedbackMeansClosed(feedbackRaw) {
  const f = normalizeArabicAlef(String(feedbackRaw || '').trim().toLowerCase());
  if (!f) return false;
  return IMPORT_CLOSE_WORDS.some(w => f.includes(w));
}
function importQuoteStatus(statusRaw) {
  const status = String(statusRaw || '').trim();
  const statusLower = status.toLowerCase();
  if (status && IMPORT_WIN_WORDS.some(w => statusLower.includes(w))) return { quoteStatus: 'po', lossReason: '', declineReason: '' };
  if (status) return { quoteStatus: 'loss', lossReason: status, declineReason: '' };
  return { quoteStatus: 'pending', lossReason: '', declineReason: '' };
}

// Any logged-in user can reach this route (not gated to a role) — instead it's
// gated by a single shared password, since this is meant as an occasional/
// emergency tool rather than a role-based permission. The password is
// intentionally not derived from any user account so it works the same for
// everyone regardless of role.
const IMPORT_SP_PASSWORD = 'UseItOnlyEmer@9173';
app.post('/api/import-sp', requirePermission('import_sp'), express.json({ limit: '15mb' }), (req, res) => {
  if (String((req.body || {}).password || '') !== IMPORT_SP_PASSWORD) {
    return res.status(403).json({ error: 'كلمة السر غير صحيحة' });
  }
  const rows = Array.isArray((req.body || {}).rows) ? req.body.rows : null;
  if (!rows || rows.length === 0) return res.status(400).json({ error: 'لا يوجد صفوف بيانات لاستيرادها' });
  if (rows.length > 20000) return res.status(400).json({ error: 'عدد الصفوف كبير جداً في مرة واحدة (الحد الأقصى 20000)' });

  const data = readData();
  // Maps a request's own code (e.g. "SP184") straight to the record object —
  // covers both records that already existed before this import started and
  // ones this import batch itself has just created, so a repeated SP number
  // is recognized in either case rather than only within the current file.
  const codeToRecordMap = new Map(data.records.map(r => [r.code, r]));
  const maxSeq = data.seqByBranch || (data.seqByBranch = {});
  const maxOfferSeq = data.offerSeqByBranch || (data.offerSeqByBranch = {});
  const bump = (obj, key, n) => { if (isFinite(n)) obj[key] = Math.max(obj[key] || 0, n); };

  const created = [];
  const merged = [];   // { rowNumber, code, item } — an extra item added to an already-known request
  const warnings = []; // { rowNumber, code, message } — row still imported when possible
  const skipped = [];  // { rowNumber, message } — row not imported at all

  rows.forEach((rawRow, idx) => {
    const rowNumber = idx + 3; // +1 for 0-index, +2 for the two header rows (English + Arabic) already stripped client-side
    const row = Array.isArray(rawRow) ? rawRow : [];
    const cell = i => (row[i] === undefined || row[i] === null) ? '' : String(row[i]).trim();
    if (row.length === 0 || row.every(c => c === '' || c === undefined || c === null)) return; // silently skip fully blank rows

    const customer = cell(1);
    const codeRaw = cell(3);
    if (!customer || !codeRaw) {
      skipped.push({ rowNumber, message: 'الصف يحتاج اسم عميل وكود SP/ACH/AXH على الأقل' });
      return;
    }

    let branchCode = importNormalizeBranch(cell(0)) || importBranchFromCode(codeRaw);
    if (!branchCode) {
      skipped.push({ rowNumber, message: `تعذر تحديد الفرع (SP/ACH/AXH) من العمود الأول أو من الكود "${codeRaw}"` });
      return;
    }

    const code = importFullCode(codeRaw, branchCode);
    // Column 9 is headed "Brand" in the sheet but the branch's own Arabic note
    // under it says البند (the item itself); column 10 is headed "P.N + type"
    // but its note says الوصف+الماركة (description+brand combined as one
    // field — the sheet doesn't keep brand separate) — so item name comes
    // from column 9 and the combined description comes from column 10.
    const item = clampStr(cell(9), MAX_LEN.item);
    const description = clampStr(cell(10), MAX_LEN.description);

    // Same SP/ACH/AXH code seen again — one request can carry several items
    // from the customer, each written on its own row in the sheet, so this
    // row is folded into the existing request as an extra item instead of
    // being treated as a duplicate request.
    const existingRec = codeToRecordMap.get(code);
    if (existingRec) {
      if (!item) {
        skipped.push({ rowNumber, code, message: 'الكود مكرر لطلب موجود بس الصف مفيهوش اسم بند (عمود Brand) لإضافته' });
        return;
      }
      const alreadyHasItem = existingRec.items.some(it => (it.item || '').trim().toLowerCase() === item.toLowerCase());
      if (alreadyHasItem) {
        skipped.push({ rowNumber, code, message: `البند "${item}" موجود بالفعل في هذا الطلب — تم تجاهل الصف كتكرار` });
        return;
      }
      existingRec.items.push({ item, description, brand: '', quantity: '', unitPrice: '', total: '', priced: false });
      merged.push({ rowNumber, code, item });
      return;
    }

    const { phone, email } = importPhoneOrEmail(cell(2));
    const offerCodeRaw = cell(14);
    const offerCode = importFullOfferCode(offerCodeRaw, branchCode);
    const feedbackRaw = cell(13);
    const { quoteStatus, lossReason, declineReason } = importQuoteStatus(cell(12));

    const dateCreated = importDate(cell(7)) || todayISO();
    const codeArrivalDate = importDate(cell(8));
    const quoteDate = importDate(cell(11));
    // Unlike the other date columns, "due date" (صالح حتى) always needs a
    // value for the quote to make sense — if the sheet's cell is empty or
    // unreadable, default to 30 days after the offer date (or the request
    // date if there's no offer date either) instead of leaving it blank.
    let quoteValidity = importDate(cell(6));
    if (!quoteValidity) {
      const base = quoteDate || dateCreated;
      const d = new Date(base + 'T00:00:00');
      if (!isNaN(d.getTime())) {
        d.setDate(d.getDate() + 30);
        quoteValidity = d.toISOString().slice(0, 10);
      }
    }
    if (cell(6) && importDate(cell(6)) === '') warnings.push({ rowNumber, code, message: 'تعذر قراءة تاريخ "due date" — تم استخدام 30 يوم بعد تاريخ العرض كتاريخ افتراضي للصلاحية' });
    if (cell(7) && importDate(cell(7)) === '') warnings.push({ rowNumber, code, message: 'تعذر قراءة "date of give code" — استُخدم تاريخ اليوم بدلاً منه' });
    if (cell(8) && !codeArrivalDate) warnings.push({ rowNumber, code, message: 'تعذر قراءة "date sent from technical" — تُركت فارغة' });
    if (cell(11) && !quoteDate) warnings.push({ rowNumber, code, message: 'تعذر قراءة "date offer was sent" — تُركت فارغة' });
    // Sanity check only — flagged, never auto-corrected, since we can't know
    // which of the two dates is the typo. Keeps the natural request-before-
    // quote order visible for a human to double check on the row itself.
    if (codeArrivalDate && codeArrivalDate < dateCreated) warnings.push({ rowNumber, code, message: 'تاريخ وصول الكود من المكتب الفني أقدم من تاريخ الطلب — راجعي ترتيب التواريخ في هذا الصف' });
    if (quoteDate && quoteDate < dateCreated) warnings.push({ rowNumber, code, message: 'تاريخ العرض أقدم من تاريخ الطلب — راجعي ترتيب التواريخ في هذا الصف' });

    // A branch writing "إغلاق"/"close" directly in the feedback column means
    // this specific request should be treated as closed, regardless of
    // whether it also has an offer — takes priority over the normal
    // offerCode-based stage choice below.
    const isClosed = importFeedbackMeansClosed(feedbackRaw);
    if (isClosed) warnings.push({ rowNumber, code, message: 'كلمة "إغلاق/close" اتلاقت في عمود feedback — تم وضع الطلب في قائمة "الطلبات المغلقة"' });

    const rec = {
      id: 'r' + Date.now() + Math.floor(Math.random() * 100000),
      code, branchCode,
      customer: clampStr(customer, MAX_LEN.customer),
      company: '',
      phone: clampStr(phone, MAX_LEN.phone),
      email: clampStr(email, MAX_LEN.email),
      items: item ? [{ item, description, brand: '', quantity: '', unitPrice: '', total: '', priced: false, colorTag: '', itemNotes: '', followupStatus: (isClosed || offerCode) ? 'إغلاق' : 'تحت التسعير', codeArrivalDate }] : [],
      orderType: importOrderType(cell(5)),
      requiredDate: '',
      salesEngineer: clampStr(cell(15), MAX_LEN.salesEngineer),
      techOfficeEngineer: '',
      notes: '',
      dateCreated,
      stage: isClosed ? 'closed' : (offerCode ? 'quote' : 'followup'),
      followupStatus: (isClosed || offerCode) ? 'إغلاق' : 'تحت التسعير',
      followupNotes: '',
      codeArrivalDate,
      offerCode,
      quoteDate,
      quoteValue: '', quoteValidity, quoteNotes: clampStr(feedbackRaw, MAX_LEN.quoteNotes),
      quoteStatus, poNumber: '', poSupplyType: '', declineReason: clampStr(declineReason, MAX_LEN.declineReason), lossReason: clampStr(lossReason, MAX_LEN.lossReason),
      inqNo: clampStr(cell(4), MAX_LEN.inqNo),
      productImages: [], sampleImages: [],
      closedAt: isClosed ? (quoteDate || dateCreated) : '',
      closedBy: isClosed ? (req.user.name + ' (استيراد من Excel)') : '',
      importedFromExcel: true, closedAt: '', closedBy: '', closeReason: '', wonAt: (quoteStatus === 'po' ? (quoteDate || dateCreated) : '')
    };
    if (!rec.items.length) warnings.push({ rowNumber, code, message: 'لا يوجد بند/صنف (عمود P.N + type) — تم استيراد الطلب بدون بنود' });

    data.records.push(rec);
    codeToRecordMap.set(code, rec);
    created.push(code);

    const seqMatch = /^[A-Za-z]+(\d+)$/.exec(code);
    if (seqMatch) bump(maxSeq, branchCode, parseInt(seqMatch[1], 10));
    if (offerCode) {
      const offerMatch = /^[A-Za-z]+Offer(\d+)$/.exec(offerCode);
      if (offerMatch) bump(maxOfferSeq, branchCode, parseInt(offerMatch[1], 10));
    }
  });

  if (created.length > 0 || merged.length > 0) {
    writeData(data);
    logActivity(req.user, 'استيراد بيانات من Excel', 'نظام', '', `تم استيراد ${created.length} طلب جديد وإضافة ${merged.length} بند لطلبات موجودة (${skipped.length} صف تم تجاهله)`);
  }

  res.json({ insertedCount: created.length, mergedCount: merged.length, skippedCount: skipped.length, warningCount: warnings.length, createdCodes: created, merged, skipped, warnings });
});

// ================= Offer document (Word) API =================
// GET returns the request's "العرض المالي" file: the user's own saved/edited
// copy if they've uploaded one back before (see POST below), otherwise a fresh
// one generated from the template + this record's current data.
app.get('/api/records/:id/offer-doc', (req, res) => {
  const data = readData();
  const rec = data.records.find(r => r.id === req.params.id);
  if (!rec) return res.status(404).json({ error: 'السجل غير موجود' });
  if (req.user.role !== 'super_admin' && recordBranch(rec) !== req.user.branchCode) {
    return res.status(403).json({ error: 'لا تملك صلاحية الوصول لهذا الطلب' });
  }
  const savedPath = offerDocPath(rec.id);
  let buf;
  try {
    buf = fs.existsSync(savedPath) ? fs.readFileSync(savedPath) : buildOfferDocx(rec);
  } catch (e) {
    console.error('offer-doc generation failed:', e);
    return res.status(500).json({ error: 'تعذر إنشاء ملف العرض المالي' });
  }
  const filename = (rec.offerCode || rec.code || 'عرض-سعر') + '.docx';
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
  res.setHeader('Content-Disposition', `attachment; filename="offer.docx"; filename*=UTF-8''${encodeURIComponent(filename)}`);
  res.send(buf);
});

// Upload the edited copy back so it becomes this record's saved offer doc —
// the GET above serves this exact file from now on, until it's replaced again.
app.post('/api/records/:id/offer-doc', requirePermission('manage_offer_docs'), express.raw({
  type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  limit: '20mb'
}), (req, res) => {
  const data = readData();
  const rec = data.records.find(r => r.id === req.params.id);
  if (!rec) return res.status(404).json({ error: 'السجل غير موجود' });
  if (req.user.role !== 'super_admin' && recordBranch(rec) !== req.user.branchCode) {
    return res.status(403).json({ error: 'لا تملك صلاحية الوصول لهذا الطلب' });
  }
  if (!Buffer.isBuffer(req.body) || req.body.length < 4 || req.body[0] !== 0x50 || req.body[1] !== 0x4B) {
    return res.status(400).json({ error: 'الملف المرفوع ليس ملف Word صالح (.docx)' });
  }
  fs.writeFileSync(offerDocPath(rec.id), req.body);
  rec.offerDocSavedAt = new Date().toISOString();
  rec.offerDocSavedBy = req.user.name;
  writeData(data);
  logActivity(req.user, 'حفظ نسخة معدّلة من العرض المالي', 'عرض مالي', rec.code, rec.customer);
  res.json({ ok: true, offerDocSavedAt: rec.offerDocSavedAt, offerDocSavedBy: rec.offerDocSavedBy });
});

// Deletes the saved/uploaded copy of the offer .docx so the GET above goes
// back to generating a fresh one from the record's current data (e.g. an
// updated price). Without this, once a copy is uploaded once, every download
// keeps serving that same old file forever even after quoteValue/items change.
app.delete('/api/records/:id/offer-doc', requirePermission('manage_offer_docs'), (req, res) => {
  const data = readData();
  const rec = data.records.find(r => r.id === req.params.id);
  if (!rec) return res.status(404).json({ error: 'السجل غير موجود' });
  if (req.user.role !== 'super_admin' && recordBranch(rec) !== req.user.branchCode) {
    return res.status(403).json({ error: 'لا تملك صلاحية الوصول لهذا الطلب' });
  }
  const savedPath = offerDocPath(rec.id);
  if (fs.existsSync(savedPath)) fs.unlinkSync(savedPath);
  rec.offerDocSavedAt = '';
  rec.offerDocSavedBy = '';
  writeData(data);
  logActivity(req.user, 'إعادة إنشاء العرض المالي من بيانات الطلب الحالية', 'عرض مالي', rec.code, rec.customer);
  res.json({ ok: true });
});

// ================= Technical offer document ("العرض الفني") API =================
// Same "save inside the program" / template-vs-uploaded-copy behavior as
// العرض المالي above — GET serves the user's own saved copy if there is one,
// otherwise a freshly generated one (buildTechnicalOfferDocx, not
// buildOfferDocx) with the pricing columns and "الشروط العامة" stripped out.
app.get('/api/records/:id/tech-offer-doc', (req, res) => {
  const data = readData();
  const rec = data.records.find(r => r.id === req.params.id);
  if (!rec) return res.status(404).json({ error: 'السجل غير موجود' });
  if (req.user.role !== 'super_admin' && recordBranch(rec) !== req.user.branchCode) {
    return res.status(403).json({ error: 'لا تملك صلاحية الوصول لهذا الطلب' });
  }
  const savedPath = techOfferDocPath(rec.id);
  let buf;
  try {
    buf = fs.existsSync(savedPath) ? fs.readFileSync(savedPath) : buildTechnicalOfferDocx(rec);
  } catch (e) {
    console.error('tech-offer-doc generation failed:', e);
    return res.status(500).json({ error: 'تعذر إنشاء ملف العرض الفني' });
  }
  const filename = 'عرض فني - ' + (rec.offerCode || rec.code || 'عرض-سعر') + '.docx';
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
  res.setHeader('Content-Disposition', `attachment; filename="tech-offer.docx"; filename*=UTF-8''${encodeURIComponent(filename)}`);
  res.send(buf);
});

app.post('/api/records/:id/tech-offer-doc', requirePermission('manage_offer_docs'), express.raw({
  type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  limit: '20mb'
}), (req, res) => {
  const data = readData();
  const rec = data.records.find(r => r.id === req.params.id);
  if (!rec) return res.status(404).json({ error: 'السجل غير موجود' });
  if (req.user.role !== 'super_admin' && recordBranch(rec) !== req.user.branchCode) {
    return res.status(403).json({ error: 'لا تملك صلاحية الوصول لهذا الطلب' });
  }
  if (!Buffer.isBuffer(req.body) || req.body.length < 4 || req.body[0] !== 0x50 || req.body[1] !== 0x4B) {
    return res.status(400).json({ error: 'الملف المرفوع ليس ملف Word صالح (.docx)' });
  }
  fs.writeFileSync(techOfferDocPath(rec.id), req.body);
  rec.techOfferDocSavedAt = new Date().toISOString();
  rec.techOfferDocSavedBy = req.user.name;
  writeData(data);
  logActivity(req.user, 'حفظ نسخة معدّلة من العرض الفني', 'عرض فني', rec.code, rec.customer);
  res.json({ ok: true, techOfferDocSavedAt: rec.techOfferDocSavedAt, techOfferDocSavedBy: rec.techOfferDocSavedBy });
});

// Same "regenerate from current data" reset as /offer-doc above, but for the
// technical offer's saved copy.
app.delete('/api/records/:id/tech-offer-doc', requirePermission('manage_offer_docs'), (req, res) => {
  const data = readData();
  const rec = data.records.find(r => r.id === req.params.id);
  if (!rec) return res.status(404).json({ error: 'السجل غير موجود' });
  if (req.user.role !== 'super_admin' && recordBranch(rec) !== req.user.branchCode) {
    return res.status(403).json({ error: 'لا تملك صلاحية الوصول لهذا الطلب' });
  }
  const savedPath = techOfferDocPath(rec.id);
  if (fs.existsSync(savedPath)) fs.unlinkSync(savedPath);
  rec.techOfferDocSavedAt = '';
  rec.techOfferDocSavedBy = '';
  writeData(data);
  logActivity(req.user, 'إعادة إنشاء العرض الفني من بيانات الطلب الحالية', 'عرض فني', rec.code, rec.customer);
  res.json({ ok: true });
});

// ================= Monthly Sales Manager Report =================
// "التقرير الشهري لمدير المبيعات" — generates the Word report for a chosen
// month AND a chosen فرع (SP / ACH / AXH), since each فرع codes its own
// requests/offers separately and the sales manager needs one report per فرع
// at a time. The branch filter is applied on top of the normal permission
// scoping (scopeRecords) so even a super_admin — who can otherwise see every
// branch — only gets the one فرع they asked for in this report.
// The template's top title line reads "(السبتية – المعرض)" for فرع SP as
// written by the sales manager; for ACH/AXH it's swapped for the branch code
// itself via the {{BRANCH_TITLE}} token (see buildMonthlyReportDocx).
// Population/column mapping for every table comes straight from the
// template the sales manager provided (see the chat that built this):
//   KPI row       -> counts below, scoped to the selected month
//   أولا (s1)     -> pending quotes, priority "عالي", expected to become a PO
//   ثانيا (s2)    -> quotes that became a PO (poSupplyType/poCurrentStatus)
//   ثالثا (s3)    -> every quote issued in the month, regardless of outcome
//   رابعا (s4)    -> requests not yet turned into a quote ("still under pricing"),
//                    one row per بند with that بند's own متابعة note
app.get('/api/reports/monthly.docx', requirePermission('view_monthly_report'), (req, res) => {
  try {
    const data = readData();
    // فرع SP هو الافتراضي لو محدش بعت branch، عشان أي رابط/زرار قديم يفضل
    // شغال زي ما كان بالظبط من غير ما يتكسر.
    const branch = BRANCH_CODES.includes(req.query.branch) ? req.query.branch : 'SP';
    const records = scopeRecords(req.user, data.records).filter(r => recordBranch(r) === branch);
    const branchTitle = branch === 'SP' ? '(السبتية – المعرض)' : branch;

    const monthRe = /^\d{4}-\d{2}$/;
    const now = new Date();
    const defaultMonth = localISOMonth(new Date(now.getFullYear(), now.getMonth(), 1));
    const month = monthRe.test(req.query.month || '') ? req.query.month : defaultMonth;
    const [y, m] = month.split('-').map(Number);
    const periodFrom = localISODate(new Date(y, m - 1, 1));
    const periodTo = localISODate(new Date(y, m, 0));
    const inPeriod = (dateStr) => !!dateStr && dateStr >= periodFrom && dateStr <= periodTo;

    const quotesInPeriod = records.filter(r => r.stage === 'quote' && inPeriod(r.quoteDate));
    const sentToCustomer = quotesInPeriod.filter(r => r.sentToCustomer);
    const poInPeriod = quotesInPeriod.filter(r => r.quoteStatus === 'po');
    const highPriorityInPeriod = records.filter(r => r.priority === 'عالي' && inPeriod(r.dateCreated));

    const kpis = {
      totalQuotes: quotesInPeriod.length,
      sentToCustomer: sentToCustomer.length,
      pendingOrDecline: quotesInPeriod.length - sentToCustomer.length,
      poCount: poInPeriod.length,
      highPriority: highPriorityInPeriod.length
    };

    const companyOf = (r) => r.company || r.customer || '';

    // أولا: pending high-priority quotes (not yet decided win/loss) — expected
    // to result in a PO.
    const section1 = quotesInPeriod
      .filter(r => r.priority === 'عالي' && r.quoteStatus === 'pending')
      .map(r => ({ company: companyOf(r), items: itemsStatement(r), value: r.quoteValue || '', customerResponse: r.customerResponse || '', actionTaken: r.actionTaken || '' }));

    // ثانيا: quotes that became a PO this month.
    const section2 = poInPeriod
      .map(r => ({ company: companyOf(r), items: itemsStatement(r), value: r.quoteValue || '', supplyType: r.poSupplyType || '', currentStatus: r.poCurrentStatus || '' }));

    // ثالثا: every quote issued this month, whatever its current status.
    const section3 = quotesInPeriod
      .map(r => ({ company: companyOf(r), items: itemsStatement(r), value: r.quoteValue || '', quoteDate: formatReportDate(r.quoteDate) }));

    // رابعا: requests that haven't become a quote yet (still being priced/
    // followed up) and weren't closed, created this month. One row per بند
    // (not per request) so each item's own متابعة note shows next to it,
    // instead of lumping every item's notes under one shared cell.
    const section4 = records
      .filter(r => (r.stage === 'request' || r.stage === 'followup') && inPeriod(r.dateCreated))
      .flatMap(r => (r.items && r.items.length ? r.items : [{ item: r.item || '', itemNotes: '' }])
        .map(it => ({ company: companyOf(r), items: it.item || '', requestDate: formatReportDate(r.dateCreated), notes: it.itemNotes || '' })));

    const buf = buildMonthlyReportDocx({ periodFrom, periodTo, branchTitle, kpis, section1, section2, section3, section4 });
    const filename = `التقرير الشهري لمدير المبيعات - ${branch} - ${month}.docx`;
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
    res.setHeader('Content-Disposition', `attachment; filename="monthly-report.docx"; filename*=UTF-8''${encodeURIComponent(filename)}`);
    res.send(buf);
  } catch (e) {
    console.error('monthly report generation failed:', e);
    res.status(500).json({ error: 'تعذر إنشاء التقرير الشهري' });
  }
});

// ================= Product images API =================
// Photos of the product attached to a quote/request — stored the same way the
// offer .docx is (saved on disk under DATA_DIR, survives restarts/backups),
// except a record can hold several of them instead of just one file.
function findRecordForImages(req, res) {
  const data = readData();
  const rec = data.records.find(r => r.id === req.params.id);
  if (!rec) { res.status(404).json({ error: 'السجل غير موجود' }); return null; }
  if (req.user.role !== 'super_admin' && recordBranch(rec) !== req.user.branchCode) {
    res.status(403).json({ error: 'لا تملك صلاحية الوصول لهذا الطلب' });
    return null;
  }
  if (!Array.isArray(rec.productImages)) rec.productImages = [];
  return { data, rec };
}

// List image metadata for a record (thumbnails/gallery are built client-side
// by fetching each image's bytes separately via the GET route below).
app.get('/api/records/:id/images', (req, res) => {
  const found = findRecordForImages(req, res);
  if (!found) return;
  res.json({ images: found.rec.productImages });
});

// Upload one product image. Sent as a raw image body (one request per file —
// the client loops over its file picker), with the original filename passed
// in the X-Image-Name header (percent-encoded) since a raw body has no field name.
app.post('/api/records/:id/images', requirePermission('manage_offer_docs'), express.raw({
  type: Object.keys(IMAGE_MIME_EXT),
  limit: '8mb'
}), (req, res) => {
  const found = findRecordForImages(req, res);
  if (!found) return;
  const { data, rec } = found;

  const mime = (req.headers['content-type'] || '').split(';')[0].trim();
  const ext = IMAGE_MIME_EXT[mime];
  if (!ext) return res.status(400).json({ error: 'صيغة الصورة غير مدعومة (JPG, PNG, WEBP, GIF فقط)' });
  if (!Buffer.isBuffer(req.body) || !looksLikeImage(req.body, mime)) {
    return res.status(400).json({ error: 'الملف المرفوع ليس صورة صالحة' });
  }
  if (rec.productImages.length >= MAX_IMAGES_PER_RECORD) {
    return res.status(400).json({ error: `الحد الأقصى ${MAX_IMAGES_PER_RECORD} صورة لكل طلب` });
  }

  let originalName = 'صورة';
  try { if (req.headers['x-image-name']) originalName = decodeURIComponent(req.headers['x-image-name']); } catch (e) { /* keep default */ }
  originalName = clampStr(String(originalName), 150);

  const imageId = 'img' + Date.now() + Math.floor(Math.random() * 1000);
  const dir = productImagesDir(rec.id);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, imageId + '.' + ext), req.body);

  const meta = {
    id: imageId, filename: originalName, mime, ext,
    size: req.body.length,
    savedAt: new Date().toISOString(), savedBy: req.user.name
  };
  rec.productImages.push(meta);
  writeData(data);
  logActivity(req.user, 'رفع صورة منتج', 'طلب', rec.code, rec.customer + (originalName ? ' — ' + originalName : ''));
  res.status(201).json(meta);
});

// Serve one image's bytes (used both to render thumbnails and full-size view).
app.get('/api/records/:id/images/:imageId', (req, res) => {
  const found = findRecordForImages(req, res);
  if (!found) return;
  const { rec } = found;
  const meta = rec.productImages.find(m => m.id === req.params.imageId);
  if (!meta) return res.status(404).json({ error: 'الصورة غير موجودة' });
  const filePath = path.join(productImagesDir(rec.id), meta.id + '.' + meta.ext);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'الصورة غير موجودة على السيرفر' });
  res.setHeader('Content-Type', meta.mime);
  res.sendFile(filePath);
});

app.delete('/api/records/:id/images/:imageId', requirePermission('manage_offer_docs'), (req, res) => {
  const found = findRecordForImages(req, res);
  if (!found) return;
  const { data, rec } = found;
  const meta = rec.productImages.find(m => m.id === req.params.imageId);
  if (!meta) return res.status(404).json({ error: 'الصورة غير موجودة' });
  rec.productImages = rec.productImages.filter(m => m.id !== req.params.imageId);
  writeData(data);
  try {
    const filePath = path.join(productImagesDir(rec.id), meta.id + '.' + meta.ext);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  } catch (e) { /* not critical */ }
  logActivity(req.user, 'حذف صورة منتج', 'طلب', rec.code, rec.customer + (meta.filename ? ' — ' + meta.filename : ''));
  res.json({ ok: true });
});

// ================= Sample images API ("صور عينة للمنتج") =================
// Second, independent photo set per request — same shape as product images
// above (same size/count limits, same validation), just its own field
// (rec.sampleImages) and its own folder (sample-images/), so the two never mix.
function findRecordForSampleImages(req, res) {
  const data = readData();
  const rec = data.records.find(r => r.id === req.params.id);
  if (!rec) { res.status(404).json({ error: 'السجل غير موجود' }); return null; }
  if (req.user.role !== 'super_admin' && recordBranch(rec) !== req.user.branchCode) {
    res.status(403).json({ error: 'لا تملك صلاحية الوصول لهذا الطلب' });
    return null;
  }
  if (!Array.isArray(rec.sampleImages)) rec.sampleImages = [];
  return { data, rec };
}

app.get('/api/records/:id/sample-images', (req, res) => {
  const found = findRecordForSampleImages(req, res);
  if (!found) return;
  res.json({ images: found.rec.sampleImages });
});

app.post('/api/records/:id/sample-images', requirePermission('manage_offer_docs'), express.raw({
  type: Object.keys(IMAGE_MIME_EXT),
  limit: '8mb'
}), (req, res) => {
  const found = findRecordForSampleImages(req, res);
  if (!found) return;
  const { data, rec } = found;

  const mime = (req.headers['content-type'] || '').split(';')[0].trim();
  const ext = IMAGE_MIME_EXT[mime];
  if (!ext) return res.status(400).json({ error: 'صيغة الصورة غير مدعومة (JPG, PNG, WEBP, GIF فقط)' });
  if (!Buffer.isBuffer(req.body) || !looksLikeImage(req.body, mime)) {
    return res.status(400).json({ error: 'الملف المرفوع ليس صورة صالحة' });
  }
  if (rec.sampleImages.length >= MAX_IMAGES_PER_RECORD) {
    return res.status(400).json({ error: `الحد الأقصى ${MAX_IMAGES_PER_RECORD} صورة لكل طلب` });
  }

  let originalName = 'صورة';
  try { if (req.headers['x-image-name']) originalName = decodeURIComponent(req.headers['x-image-name']); } catch (e) { /* keep default */ }
  originalName = clampStr(String(originalName), 150);

  const imageId = 'smp' + Date.now() + Math.floor(Math.random() * 1000);
  const dir = sampleImagesDir(rec.id);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, imageId + '.' + ext), req.body);

  const meta = {
    id: imageId, filename: originalName, mime, ext,
    size: req.body.length,
    savedAt: new Date().toISOString(), savedBy: req.user.name
  };
  rec.sampleImages.push(meta);
  writeData(data);
  logActivity(req.user, 'رفع صورة عينة', 'طلب', rec.code, rec.customer + (originalName ? ' — ' + originalName : ''));
  res.status(201).json(meta);
});

app.get('/api/records/:id/sample-images/:imageId', (req, res) => {
  const found = findRecordForSampleImages(req, res);
  if (!found) return;
  const { rec } = found;
  const meta = rec.sampleImages.find(m => m.id === req.params.imageId);
  if (!meta) return res.status(404).json({ error: 'الصورة غير موجودة' });
  const filePath = path.join(sampleImagesDir(rec.id), meta.id + '.' + meta.ext);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'الصورة غير موجودة على السيرفر' });
  res.setHeader('Content-Type', meta.mime);
  res.sendFile(filePath);
});

app.delete('/api/records/:id/sample-images/:imageId', requirePermission('manage_offer_docs'), (req, res) => {
  const found = findRecordForSampleImages(req, res);
  if (!found) return;
  const { data, rec } = found;
  const meta = rec.sampleImages.find(m => m.id === req.params.imageId);
  if (!meta) return res.status(404).json({ error: 'الصورة غير موجودة' });
  rec.sampleImages = rec.sampleImages.filter(m => m.id !== req.params.imageId);
  writeData(data);
  try {
    const filePath = path.join(sampleImagesDir(rec.id), meta.id + '.' + meta.ext);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  } catch (e) { /* not critical */ }
  logActivity(req.user, 'حذف صورة عينة', 'طلب', rec.code, rec.customer + (meta.filename ? ' — ' + meta.filename : ''));
  res.json({ ok: true });
});

// ================= Customers (aggregated from records — the sidebar "العملاء" list) =================
app.get('/api/customers', requirePermission('view_customers'), (req, res) => {
  const scopeKey = req.user.role === 'super_admin' ? 'ALL' : req.user.branchCode;
  let cached = customersCache.get(scopeKey);
  if (!cached) {
    const data = readData();
    const scoped = scopeRecords(req.user, data.records);
    const map = {};
    scoped.forEach(r => {
      const key = (r.phone && r.phone.trim()) ? 'p:' + r.phone.trim() : 'n:' + r.customer + '|' + (r.company || '');
      if (!map[key]) {
        map[key] = {
          name: r.customer, company: r.company || '', phone: r.phone || '', email: r.email || '',
          requestsCount: 0, quotesCount: 0, wonCount: 0, lastDate: r.dateCreated, lastCode: r.code
        };
      }
      const c = map[key];
      c.requestsCount++;
      if (r.stage === 'quote') c.quotesCount++;
      if (r.quoteStatus === 'po') c.wonCount++;
      if (r.dateCreated >= c.lastDate) { c.lastDate = r.dateCreated; c.lastCode = r.code; }
      c.phone = c.phone || r.phone || '';
      c.email = c.email || r.email || '';
      c.company = c.company || r.company || '';
    });
    cached = { customers: Object.values(map).sort((a, b) => b.lastDate.localeCompare(a.lastDate)) };
    customersCache.set(scopeKey, cached);
  }
  res.json(cached);
});


// ================= Activity log API =================
// Grantable via view_activity_log, but a non-super-admin only ever sees
// their OWN branch's entries — activity entries don't carry a branchCode
// field directly, so it's parsed from entityCode the same way recordBranch()
// falls back to the code's letter prefix for older records. Entries with no
// branch-shaped entityCode (logins, user-management actions) are cross-branch/
// administrative by nature and stay super_admin-only.
function activityEntryBranch(entry) {
  const m = /^([A-Za-z]+)\d+$/.exec(entry.entityCode || '');
  return (m && BRANCH_CODES.includes(m[1])) ? m[1] : null;
}
app.get('/api/activity', requirePermission('view_activity_log'), (req, res) => {
  const activity = readActivity();
  if (req.user.role === 'super_admin') return res.json(activity);
  res.json({ log: activity.log.filter(e => activityEntryBranch(e) === req.user.branchCode) });
});

// ================= Notifications & Internal Chat =================
// The "تنبيهات الطلبات والعروض" (alerts) page lists requests/quotes that need
// attention. This lets someone looking at an alert row notify a specific
// colleague about it — picking who, writing them a note — which: (1) opens a
// small chat thread scoped to that one record between the two of them so they
// can go back and forth, and (2) writes a line into the activity log tied to
// that record's code, so there's a standing, timestamped record that the
// colleague was in fact told, not just a message that could get lost.
//
// A thread is keyed by (record code + the two participants' ids) so
// re-notifying the same person about the same alert reuses the existing
// conversation instead of splintering it into a new one each time.
function threadKeyFor(recordCode, idA, idB) {
  const ids = [idA, idB].sort();
  return `${recordCode}__${ids[0]}__${ids[1]}`;
}
function findOrCreateThread(chats, recordCode, recordLabel, userA, userB) {
  const key = threadKeyFor(recordCode, userA.id, userB.id);
  let t = chats.threads.find(x => x.key === key);
  if (!t) {
    t = {
      id: 't' + Date.now() + Math.floor(Math.random() * 1000),
      key, recordCode,
      recordLabel: recordLabel || recordCode,
      participants: [userA.id, userB.id],
      participantNames: { [userA.id]: userA.name, [userB.id]: userB.name },
      createdAt: new Date().toISOString(),
      lastMessageAt: new Date().toISOString(),
      lastRead: {},
      messages: []
    };
    chats.threads.unshift(t);
  } else {
    // Keep display names fresh in case either side's account name changed
    // since the thread was first created.
    t.participantNames[userA.id] = userA.name;
    t.participantNames[userB.id] = userB.name;
    if (recordLabel) t.recordLabel = recordLabel;
  }
  return t;
}
// Lightweight "who can I notify" list — unlike GET /api/users this is open to
// every logged-in role (not just super_admin), since picking a colleague to
// flag an alert to isn't an admin action. Scoped the same way records are:
// your own branch's people, plus every super_admin (who can see/act on any
// branch), minus the protected Ultra Admin account and yourself.
function usersDirectoryFor(user) {
  const all = readUsers().users.filter(u => !u.protected);
  const visible = user.role === 'super_admin' ? all : all.filter(u => u.branchCode === user.branchCode || u.role === 'super_admin');
  return visible.filter(u => u.id !== user.id).map(u => ({ id: u.id, name: u.name, username: u.username, role: u.role, branchCode: u.branchCode || 'SP' }));
}
app.get('/api/users/directory', (req, res) => {
  res.json({ users: usersDirectoryFor(req.user) });
});

// Notify a colleague about a specific alert row. Creates/reuses the chat
// thread between the two of them, posts the note as the first message, and
// logs it against the record's code so it's provable later.
app.post('/api/alerts/notify', (req, res) => {
  const { recordCode, recordLabel, toUserId, note } = req.body || {};
  if (!recordCode || typeof recordCode !== 'string') return res.status(400).json({ error: 'الطلب/العرض غير محدد' });
  if (!toUserId || typeof toUserId !== 'string') return res.status(400).json({ error: 'من فضلك اختار المستخدم اللي عايز تنبهه' });
  if (!note || !String(note).trim()) return res.status(400).json({ error: 'من فضلك اكتب ملحوظة قصيرة له' });

  const target = readUsers().users.find(u => u.id === toUserId && !u.protected);
  if (!target) return res.status(404).json({ error: 'المستخدم غير موجود' });
  if (target.id === req.user.id) return res.status(400).json({ error: 'لا يمكنك تنبيه نفسك' });

  const cleanNote = clampStr(String(note).trim(), MAX_LEN.chatMessage);
  const cleanCode = clampStr(String(recordCode).trim(), 100);
  const cleanLabel = recordLabel ? clampStr(String(recordLabel).trim(), MAX_LEN.recordLabel) : cleanCode;

  const chats = readChats();
  const thread = findOrCreateThread(chats, cleanCode, cleanLabel, req.user, publicUser(target));
  const msg = { id: 'm' + Date.now() + Math.floor(Math.random() * 1000), from: req.user.id, fromName: req.user.name, text: cleanNote, at: new Date().toISOString(), isNotification: true };
  thread.messages.push(msg);
  thread.lastMessageAt = msg.at;
  thread.lastRead[req.user.id] = msg.at; // the sender has obviously already "read" their own note
  writeChats(chats);

  logActivity(req.user, 'تنبيه موظف', 'تنبيه', cleanCode, `تم تنبيه: ${target.name} — الملحوظة: ${cleanNote}`);

  res.status(201).json({ threadId: thread.id });
});

// This user's chat inbox: every thread they're part of, newest activity
// first, with an unread count computed from their own last-read marker.
app.get('/api/chats', (req, res) => {
  const chats = readChats();
  const mine = chats.threads.filter(t => t.participants.includes(req.user.id));
  const out = mine.map(t => {
    const otherId = t.participants.find(id => id !== req.user.id);
    const last = t.messages[t.messages.length - 1];
    const lastReadAt = t.lastRead[req.user.id] || null;
    const unread = t.messages.filter(m => m.from !== req.user.id && (!lastReadAt || m.at > lastReadAt)).length;
    return {
      id: t.id, recordCode: t.recordCode, recordLabel: t.recordLabel,
      otherUserId: otherId || null, otherUserName: (otherId && t.participantNames[otherId]) || '—',
      lastMessage: last ? last.text : '', lastMessageAt: t.lastMessageAt,
      lastMessageFromMe: last ? last.from === req.user.id : false,
      unread
    };
  }).sort((a, b) => (b.lastMessageAt || '').localeCompare(a.lastMessageAt || ''));
  res.json({ threads: out });
});

// One thread's full messages. Opening it marks it read for this user (so the
// unread badge clears) — a plain writeJSON, not writeChats, since a read
// doesn't need to ping every other tab the way a new message does.
app.get('/api/chats/:id', (req, res) => {
  const chats = readChats();
  const t = chats.threads.find(x => x.id === req.params.id);
  if (!t || !t.participants.includes(req.user.id)) return res.status(404).json({ error: 'المحادثة غير موجودة' });
  t.lastRead[req.user.id] = new Date().toISOString();
  writeJSON(CHATS_FILE, chats);
  const otherId = t.participants.find(id => id !== req.user.id);
  res.json({
    id: t.id, recordCode: t.recordCode, recordLabel: t.recordLabel,
    otherUserId: otherId || null, otherUserName: (otherId && t.participantNames[otherId]) || '—',
    messages: t.messages
  });
});

app.post('/api/chats/:id/messages', (req, res) => {
  const { text } = req.body || {};
  if (!text || !String(text).trim()) return res.status(400).json({ error: 'اكتب رسالة' });
  const chats = readChats();
  const t = chats.threads.find(x => x.id === req.params.id);
  if (!t || !t.participants.includes(req.user.id)) return res.status(404).json({ error: 'المحادثة غير موجودة' });
  const msg = { id: 'm' + Date.now() + Math.floor(Math.random() * 1000), from: req.user.id, fromName: req.user.name, text: clampStr(String(text).trim(), MAX_LEN.chatMessage), at: new Date().toISOString() };
  t.messages.push(msg);
  t.lastMessageAt = msg.at;
  t.lastRead[req.user.id] = msg.at;
  writeChats(chats);
  res.status(201).json(msg);
});

// ================= Users & permissions API (super admin only) =================
// Only the super admin manages accounts — a branch admin never gets to create,
// promote, or even see accounts belonging to other branches.
app.get('/api/users', requireSuperAdmin, (req, res) => {
  const users = readUsers();
  // The protected "Ultra Admin" account is invisible to everyone except
  // itself — even to other super_admin accounts. This keeps it out of the
  // list entirely rather than just hiding it in the UI, so there's no id to
  // even attempt targeting with a PATCH/DELETE call.
  const visible = req.user.protected ? users.users : users.users.filter(u => !u.protected);
  res.json({ users: visible.map(publicUser) });
});

// Flat key->Arabic-label lookup, built once from PERMISSION_GROUPS, used to
// write a readable "granted X / revoked Y" line whenever a user's
// permissions change (see describePermissionChanges below).
const PERMISSION_LABELS_AR = {};
// for (const g of require('./public/js/permissions').PERMISSION_GROUPS) {
//   for (const p of g.perms) PERMISSION_LABELS_AR[p.key] = p.label_ar;
// }
function describePermissionChanges(before, after) {
  const lines = [];
  for (const key of GRANTABLE_PERMISSION_KEYS) {
    const b = !!before[key], a = !!after[key];
    if (b !== a) lines.push(`${a ? '✓ منح' : '✗ إلغاء'}: ${PERMISSION_LABELS_AR[key] || key}`);
  }
  return lines;
}
app.post('/api/users', requireSuperAdmin, (req, res) => {
  const { username, password, name, role, branchCode, permissions } = req.body || {};
  if (!username || !password || !name || !role) {
    return res.status(400).json({ error: 'كل الحقول مطلوبة' });
  }
  if (typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'كلمة المرور لازم تكون 8 حروف/أرقام على الأقل' });
  }
  if (!['super_admin', 'admin', 'viewer'].includes(role)) {
    return res.status(400).json({ error: 'صلاحية غير معروفة' });
  }
  if (branchCode && !BRANCH_CODES.includes(branchCode)) {
    return res.status(400).json({ error: 'كود الفرع غير معروف' });
  }
  const users = readUsers();
  if (users.users.some(u => u.username === username)) {
    return res.status(400).json({ error: 'اسم المستخدم مستخدم بالفعل' });
  }
  const salt = makeSalt();
  const u = { id: 'u' + Date.now(), username, name, role, branchCode: branchCode || 'SP', salt, hash: hashPassword(password, salt), permissions: sanitizePermissions(permissions) };
  users.users.push(u);
  writeUsers(users);
  const permLines = describePermissionChanges({}, u.permissions);
  logActivity(req.user, 'إضافة مستخدم جديد', 'مستخدم', username, [`الاسم: ${name} | الصلاحية: ${role} | الفرع: ${u.branchCode}`, ...permLines].join('\n'));
  res.status(201).json(publicUser(u));
});

app.patch('/api/users/:id', requireSuperAdmin, (req, res) => {
  const users = readUsers();
  const u = users.users.find(x => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: 'المستخدم غير موجود' });
  // The protected account (Ultra Admin) can only ever be edited by itself —
  // no other super_admin can change its name/role/branch/password, even if
  // they somehow know its id. It never appears in GET /api/users to anyone
  // else, so this is defense-in-depth on top of that.
  if (u.protected && req.user.id !== u.id) {
    return res.status(403).json({ error: 'هذا حساب محمي، ولا يمكن تعديله إلا من صاحبه' });
  }

  const { name, role, password, branchCode, permissions } = req.body || {};
  if (name) u.name = name;
  if (role) {
    if (!['super_admin', 'admin', 'viewer'].includes(role)) return res.status(400).json({ error: 'صلاحية غير معروفة' });
    if (u.role === 'super_admin' && role !== 'super_admin') {
      const otherSuperAdmins = users.users.filter(x => x.role === 'super_admin' && x.id !== u.id);
      if (otherSuperAdmins.length === 0) return res.status(400).json({ error: 'لا يمكن ترك النظام بدون مدير عام (Super Admin) واحد على الأقل' });
    }
    u.role = role;
  }
  if (branchCode) {
    if (!BRANCH_CODES.includes(branchCode)) return res.status(400).json({ error: 'كود الفرع غير معروف' });
    u.branchCode = branchCode;
  }
  if (password) {
    if (typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({ error: 'كلمة المرور لازم تكون 8 حروف/أرقام على الأقل' });
    }
    u.salt = makeSalt();
    u.hash = hashPassword(password, u.salt);
  }
  let permLines = [];
  if (permissions !== undefined) {
    const before = u.permissions || {};
    u.permissions = sanitizePermissions(permissions);
    permLines = describePermissionChanges(before, u.permissions);
  }
  writeUsers(users);
  logActivity(req.user, 'تعديل بيانات مستخدم', 'مستخدم', u.username, [`الاسم: ${u.name} | الصلاحية: ${u.role} | الفرع: ${u.branchCode || 'SP'}`, ...permLines].join('\n'));
  res.json(publicUser(u));
});

app.delete('/api/users/:id', requireSuperAdmin, (req, res) => {
  const users = readUsers();
  const u = users.users.find(x => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: 'المستخدم غير موجود' });
  if (u.protected) return res.status(403).json({ error: 'لا يمكن حذف الحساب المحمي (Ultra Admin)' });
  if (u.id === req.user.id) return res.status(400).json({ error: 'لا يمكنك حذف حسابك الحالي' });
  if (u.role === 'super_admin') {
    const otherSuperAdmins = users.users.filter(x => x.role === 'super_admin' && x.id !== u.id);
    if (otherSuperAdmins.length === 0) return res.status(400).json({ error: 'لا يمكن حذف آخر مدير عام (Super Admin) في النظام' });
  }
  users.users = users.users.filter(x => x.id !== u.id);
  writeUsers(users);
  logActivity(req.user, 'حذف مستخدم', 'مستخدم', u.username, `الاسم: ${u.name}`);
  res.json({ ok: true });
});

// ================= Daily automatic backup =================
// Copies the JSON "tables" (requests/quotes, users, activity log, internal
// notify-chat threads) into: backups/<YYYY-MM-DD_HH-mm-ss>/
// Runs once at startup (if today's backup doesn't exist yet) and then every 24h.
// Old backups beyond BACKUP_KEEP_DAYS are deleted automatically so the folder
// doesn't grow forever.
const BACKUP_KEEP_DAYS = 30;

// Includes milliseconds (not just seconds) specifically so two backups that
// happen within the same second — e.g. the automatic "safety" backup that
// /api/backup/restore takes right before restoring, landing in the same
// second as a backup someone had just manually taken — never collide on the
// same folder name. A folder-name collision would mean the second backup's
// mkdirSync silently reuses the first backup's folder and overwrites its
// files, which would then make a restore silently restore the wrong data.
function timestampFolder() {
  const d = new Date();
  const pad = (n, w = 2) => String(n).padStart(w, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}_${pad(d.getHours())}-${pad(d.getMinutes())}-${pad(d.getSeconds())}-${pad(d.getMilliseconds(), 3)}`;
}

// Recursively copies a folder's contents into a backup folder. Used for
// product-images/ and offer-docs/, which (unlike the three JSON "tables")
// aren't single files, so they need their own copy step. Skips entirely if
// the source folder doesn't exist or is empty, so a fresh install with no
// uploaded images/offer docs yet doesn't clutter every backup with empty
// folders. Plain fs.readdirSync/copyFileSync (no fs.cpSync) so this still
// works on Node 16, matching the README's minimum version.
function copyDirRecursive(src, dest) {
  if (!fs.existsSync(src)) return;
  const entries = fs.readdirSync(src, { withFileTypes: true });
  if (entries.length === 0) return;
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of entries) {
    const s = path.join(src, entry.name);
    const d = path.join(dest, entry.name);
    if (entry.isDirectory()) copyDirRecursive(s, d);
    else fs.copyFileSync(s, d);
  }
}

async function backupNow(reason) {
  try {
    // These JSON "tables" now live in memory and only hit disk on a short
    // debounce (see the caching layer above) — flush any pending change first
    // so a backup taken right after an edit never misses it.
    await flushAllWrites();
    if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });
    const folder = path.join(BACKUP_DIR, timestampFolder());
    fs.mkdirSync(folder, { recursive: true });
    for (const f of [DATA_FILE, USERS_FILE, ACTIVITY_FILE, CHATS_FILE]) {
      if (fs.existsSync(f)) fs.copyFileSync(f, path.join(folder, path.basename(f)));
    }
    // Uploaded product photos and saved offer .docx files live on disk outside
    // the JSON files above — copy them into the backup too so a restore
    // brings back everything the program stores, not just the JSON records.
    copyDirRecursive(PRODUCT_IMAGES_DIR, path.join(folder, 'product-images'));
    copyDirRecursive(SAMPLE_IMAGES_DIR, path.join(folder, 'sample-images'));
    copyDirRecursive(OFFER_DOCS_DIR, path.join(folder, 'offer-docs'));
    cleanupOldBackups();
    console.log(`✔ تم عمل نسخة احتياطية (${reason || 'تلقائي'}) في: ${folder}`);
    return folder;
  } catch (e) {
    console.error('⚠ فشل عمل النسخة الاحتياطية:', e.message);
    return null;
  }
}

function cleanupOldBackups() {
  if (!fs.existsSync(BACKUP_DIR)) return;
  const cutoff = Date.now() - BACKUP_KEEP_DAYS * 24 * 60 * 60 * 1000;
  for (const name of fs.readdirSync(BACKUP_DIR)) {
    const full = path.join(BACKUP_DIR, name);
    try {
      const stat = fs.statSync(full);
      if (stat.isDirectory() && stat.mtimeMs < cutoff) {
        fs.rmSync(full, { recursive: true, force: true });
      }
    } catch (e) { /* ignore a single bad entry */ }
  }
}

function hasBackupToday() {
  if (!fs.existsSync(BACKUP_DIR)) return false;
  const today = todayISO();
  return fs.readdirSync(BACKUP_DIR).some(name => name.startsWith(today));
}

// Kick things off: back up now if today doesn't have one yet, then every 24h.
if (!hasBackupToday()) backupNow('عند بدء التشغيل');
setInterval(() => backupNow('يومي مجدول'), 24 * 60 * 60 * 1000).unref();

// Manual backup trigger + listing, admin only.
app.post('/api/backup/now', requireUltraAdmin, async (req, res) => {
  const folder = await backupNow('يدوي بواسطة ' + req.user.name);
  if (!folder) return res.status(500).json({ error: 'فشل عمل النسخة الاحتياطية' });
  logActivity(req.user, 'System Snapshot', 'نظام', '', folder);
  res.json({ ok: true, folder });
});
app.get('/api/backup/list', requireUltraAdmin, (req, res) => {
  if (!fs.existsSync(BACKUP_DIR)) return res.json({ backups: [], folder: BACKUP_DIR });
  const backups = fs.readdirSync(BACKUP_DIR)
    .filter(name => fs.statSync(path.join(BACKUP_DIR, name)).isDirectory())
    .sort((a, b) => b.localeCompare(a));
  res.json({ backups, folder: BACKUP_DIR });
});

// Recursively lists every file inside a folder as { relPath, absPath } pairs,
// with relPath using forward slashes (zip entry names are always '/', even on
// Windows) — used to build the download-as-zip response below.
function listFilesRecursive(dir, baseRel) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const abs = path.join(dir, entry.name);
    const rel = baseRel ? baseRel + '/' + entry.name : entry.name;
    if (entry.isDirectory()) out.push(...listFilesRecursive(abs, rel));
    else out.push({ relPath: rel, absPath: abs });
  }
  return out;
}
// Only accept the exact timestamp-folder shape backupNow() generates
// (YYYY-MM-DD_HH-mm-ss) as the :name param — this both validates the backup
// exists and rules out any path-traversal attempt (e.g. "../../etc") before
// it ever reaches path.join, since nothing else can match the pattern.
const BACKUP_NAME_RE = /^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}-\d{3}$/;

// Packages one backup folder (the JSON "tables" + any product-images/offer-docs
// subfolders it has) into a single .zip and streams it down as a file
// download — this is what lets the ultra admin grab a full local copy from a
// cloud deployment with no SSH/file-manager access, straight from the browser.
app.get('/api/backup/download/:name', requireUltraAdmin, (req, res) => {
  const name = req.params.name;
  if (!BACKUP_NAME_RE.test(name)) return res.status(400).json({ error: 'اسم نسخة احتياطية غير صالح' });
  const folder = path.join(BACKUP_DIR, name);
  if (!fs.existsSync(folder) || !fs.statSync(folder).isDirectory()) {
    return res.status(404).json({ error: 'النسخة الاحتياطية غير موجودة' });
  }
  try {
    const files = listFilesRecursive(folder, '');
    const entries = files.map(f => ({ relPath: f.relPath, data: fs.readFileSync(f.absPath) }))
      .map(f => ({ name: f.relPath, data: f.data }));
    const zipBuffer = zip(entries);
    // No separate logActivity call here on purpose: in this program's only
    // UI flow, a download always immediately follows POST /api/backup/now
    // (which already logged "System Snapshot" for the same click) — so this
    // stays one log line per backup button click instead of two.
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="backup-${name}.zip"`);
    res.send(zipBuffer);
  } catch (e) {
    console.error('⚠ فشل تجهيز ملف الباك أب للتنزيل:', e.message);
    res.status(500).json({ error: 'حدث خطأ أثناء تجهيز ملف التنزيل' });
  }
});

// Wipes and re-populates a live folder from a backup subfolder. Used for
// product-images/ and offer-docs/ during restore. If the backup doesn't have
// this subfolder at all (either it was empty at backup time, or it's an old
// backup taken before this folder was included in backups), the live folder
// is left untouched — restoring is never allowed to silently delete files
// that a given backup simply has no information about either way.
function replaceDirFromBackup(backupSubdir, liveDir) {
  if (!fs.existsSync(backupSubdir)) return false;
  fs.rmSync(liveDir, { recursive: true, force: true });
  fs.mkdirSync(liveDir, { recursive: true });
  copyDirRecursive(backupSubdir, liveDir);
  return true;
}

// Restores the system to a previous backup snapshot — the other half of the
// backup feature, and the one that actually lets a mistake or a crash be
// Shared restore logic used by both restore routes below (folder-based, and
// upload-a-zip-based) — everything except "where do the bytes for a given
// file/folder come from" is identical, so that lookup is the only thing
// injected. getFileBuffer(basename) -> Buffer|null for data/users/activity/
// chats json; restoreDir(prefix, liveDir) -> bool, wipes+repopulates liveDir from
// the backup's <prefix>/ folder if the backup has one, else leaves it alone
// (same "never guess-delete" rule as replaceDirFromBackup below).
async function performRestore(req, getFileBuffer, restoreDir, restoreLabel) {
  const safetyFolder = await backupNow('نسخة أمان تلقائية قبل الاسترجاع إلى ' + restoreLabel);

  const restoredFiles = [];
  for (const f of [DATA_FILE, USERS_FILE, ACTIVITY_FILE, CHATS_FILE]) {
    const buf = getFileBuffer(path.basename(f));
    if (!buf) continue; // this backup never had this file — leave the live one as-is
    writeJSON(f, JSON.parse(buf.toString('utf-8'))); // updates the in-memory cache immediately, not just disk
    restoredFiles.push(path.basename(f));
  }
  await flushAllWrites(); // persist right away, not on the usual debounce

  const restoredImages = restoreDir('product-images', PRODUCT_IMAGES_DIR);
  const restoredSampleImages = restoreDir('sample-images', SAMPLE_IMAGES_DIR);
  const restoredDocs = restoreDir('offer-docs', OFFER_DOCS_DIR);

  ensureProtectedAdmin();
  logActivity(req.user, 'استرجاع نسخة احتياطية', 'نظام', '', `تم الاسترجاع إلى: ${restoreLabel}`);
  for (const t of Object.keys(sessions)) delete sessions[t];

  console.log(`✔ تم استرجاع نسخة احتياطية (${restoreLabel}) بواسطة ${req.user.name} — نسخة أمان أُخذت قبلها في: ${safetyFolder}`);
  return { restoredFiles, restoredImages, restoredSampleImages, restoredDocs, safetyBackup: safetyFolder ? path.basename(safetyFolder) : null };
}

// undone. Ultra-admin only (requireUltraAdmin, same as every other backup
// action) since this overwrites every order, user account, and activity log
// entry with whatever they looked like at backup time.
//
// Safety net: before touching anything, this takes a fresh backup of the
// CURRENT live data first (tagged "قبل الاسترجاع") — so restoring the wrong
// snapshot by mistake is itself always undoable by restoring that one.
app.post('/api/backup/restore/:name', requireUltraAdmin, async (req, res) => {
  const name = req.params.name;
  if (!BACKUP_NAME_RE.test(name)) return res.status(400).json({ error: 'اسم نسخة احتياطية غير صالح' });
  const folder = path.join(BACKUP_DIR, name);
  if (!fs.existsSync(folder) || !fs.statSync(folder).isDirectory()) {
    return res.status(404).json({ error: 'النسخة الاحتياطية غير موجودة' });
  }
  try {
    const getFileBuffer = (basename) => {
      const p = path.join(folder, basename);
      return fs.existsSync(p) ? fs.readFileSync(p) : null;
    };
    const restoreDir = (prefix, liveDir) => replaceDirFromBackup(path.join(folder, prefix), liveDir);
    const result = await performRestore(req, getFileBuffer, restoreDir, name);
    res.json({ ok: true, ...result });
  } catch (e) {
    console.error('⚠ فشل استرجاع النسخة الاحتياطية:', e.message);
    res.status(500).json({ error: 'حدث خطأ أثناء الاسترجاع: ' + e.message });
  }
});

// Restores from a backup .zip the ultra admin uploads from their own device —
// e.g. one downloaded earlier via the backup button and kept somewhere
// outside the program's own backups/ folder (a laptop, an external drive,
// cloud storage). Same safety net and behavior as the folder-based restore
// above (performRestore), just reading from the uploaded zip's entries
// instead of a folder already sitting in BACKUP_DIR.
app.post('/api/backup/restore-upload', requireUltraAdmin, express.raw({
  type: ['application/zip', 'application/x-zip-compressed', 'application/octet-stream'],
  limit: '300mb'
}), async (req, res) => {
  if (!Buffer.isBuffer(req.body) || req.body.length < 4) {
    return res.status(400).json({ error: 'لم يتم استلام أي ملف' });
  }
  let entries;
  try {
    entries = unzip(req.body);
  } catch (e) {
    return res.status(400).json({ error: 'الملف المرفوع ليس ملف ZIP صالح' });
  }
  const hasCoreFile = ['data.json', 'users.json', 'activity.json'].some(n => entries.has(n));
  if (!hasCoreFile) {
    return res.status(400).json({ error: 'هذا الملف لا يبدو نسخة احتياطية صالحة لهذا البرنامج (لا يحتوي على data.json أو users.json أو activity.json)' });
  }
  try {
    const getFileBuffer = (basename) => entries.has(basename) ? entries.get(basename) : null;
    const restoreDir = (prefix, liveDir) => {
      const relevant = [];
      for (const [name, data] of entries) {
        if (name.startsWith(prefix + '/') && name.length > prefix.length + 1) {
          relevant.push({ relPath: name.slice(prefix.length + 1), data });
        }
      }
      if (!relevant.length) return false;
      fs.rmSync(liveDir, { recursive: true, force: true });
      fs.mkdirSync(liveDir, { recursive: true });
      for (const { relPath, data } of relevant) {
        const dest = path.join(liveDir, relPath);
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        fs.writeFileSync(dest, data);
      }
      return true;
    };
    const result = await performRestore(req, getFileBuffer, restoreDir, 'ملف مرفوع من الجهاز');
    res.json({ ok: true, ...result });
  } catch (e) {
    console.error('⚠ فشل استرجاع النسخة الاحتياطية المرفوعة:', e.message);
    res.status(500).json({ error: 'حدث خطأ أثناء الاسترجاع: ' + e.message });
  }
});

// Simple liveness endpoint most cloud platforms (Render, Railway, Fly, Docker,
// Kubernetes...) can poll to confirm the container is up and responding.
app.get('/health', (req, res) => res.json({ ok: true }));

// ================= Fallbacks: unknown API routes + centralized error handler =================
app.use('/api', (req, res) => res.status(404).json({ error: 'المسار غير موجود' }));
// Catches JSON parse errors from express.json() and any other unhandled error,
// so the client always gets a clean JSON error instead of an HTML stack trace.
app.use((err, req, res, next) => {
  console.error('⚠ خطأ غير متوقع:', err.message);
  res.status(err.status || 500).json({ error: 'حدث خطأ غير متوقع في السيرفر' });
});

const server = app.listen(PORT, HOST, () => {
  console.log(`✔ نظام تكويد طلبات العملاء يعمل على: http://${DISPLAY_IP}:${PORT}`);
  console.log(`  مجلد البيانات: ${DATA_DIR}`);
  console.log(`  النسخ الاحتياطية اليومية بتتحفظ في: ${BACKUP_DIR}`);
});

// Graceful shutdown: cloud platforms (Render, Railway, Fly, Docker, k8s...) send
// SIGTERM before killing a container on redeploy/restart/scale-down. Closing the
// server cleanly avoids cutting off a request that's mid-write.
function shutdown(signal) {
  console.log(`${signal} received, shutting down...`);
  // Long-lived /api/events (SSE) connections never end on their own, and
  // server.close()'s callback below waits for every open connection to end —
  // without this, an open browser tab would make a graceful shutdown hang
  // until the 5s force-exit kicked in instead of exiting cleanly.
  for (const client of sseClients) { try { client.end(); } catch (e) { /* ignore */ } }
  // Data is only guaranteed on disk after the debounced background write
  // runs (see the caching layer above) — flush whatever's pending first so a
  // redeploy/restart never loses the last few seconds of edits.
  server.close(() => { flushAllWrites().finally(() => process.exit(0)); });
  // Force-exit if something keeps the process alive too long.
  setTimeout(() => process.exit(0), 5000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
