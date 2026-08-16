"use strict";
import { createHash } from "node:crypto";

// room-store.js — S2 房间 DO 的 SQL 落库逻辑，与「用 Cloudflare DO 的
// ctx.storage.sql 跑」还是「用 node:sqlite 跑」完全解耦。
//
// 这个模块只依赖一个最小 sql 适配器接口：
//   sql.exec(query, ...params) -> Array<对象行>
// - room-do.js 用一个薄适配器包 Cloudflare 的 ctx.storage.sql.exec(...).toArray()；
// - test/room-store.test.js 用一个薄适配器包 Node 内建的 node:sqlite。
// 两边跑的是同一份逻辑代码，不是「测试重写一遍、生产另写一遍」——不存在两套
// 逻辑漂移的风险，这也是为什么本骨架敢说 seq/epoch/回放/配额这几块逻辑是
// 「真被测过」而不是「照抄了一份看起来像的假逻辑」。
//
// DO wiring（Hibernation API / WebSocketPair / serializeAttachment 那部分）
// 没有等价的可单测替身，只能等 `wrangler dev` 真机手验——这在 room-do.js
// 顶部注释里也标了。

const CLIENT_MSG_ID_NAMESPACE = "fe4e51ad-468c-4c11-85c2-f15f0c22f030";
const CLAIM_LIMIT = 30;
const CLAIM_WINDOW_MS = 60 * 60 * 1000;
const TOKEN_TTL_SKEW_MS = 120_000;
const TOKEN_TTL_CAPS_MS = Object.freeze({
  pairing: 330_000,
  access: 3_900_000,
  prev: 172_800_000,
  refresh_until: 2_592_000_000,
});
const TOKEN_HASH_RE = /^[0-9a-f]{64}$/;
const DEVICE_SUBJECT_RE = /^device:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

// SEC-1：ip_bucket_salt 从 room_meta（业务 schema，鉴权成功后才建）迁到
// room_state（哨兵表，恒存在）——deriveIpBucketKey 在鉴权前（S1i2 §9.8）就要
// 用盐派生 per-IP 桶键，若盐仍挂业务 schema，鉴权前建盐这一步就会把业务表
// 拽回鉴权前无条件建的老问题（见本单背景）。
// SEC-3：created_at 供未认领空房的固定回收截止（created_at +
// UNCLAIMED_RECLAIM_MS，见 room-do.js scheduleNextTokenAlarm/alarm）——固定
// 不滑动，同一套「哨兵表恒存在」纪律，理由同上方 ip_bucket_salt 注释。
const ROOM_STATE_SCHEMA = `CREATE TABLE IF NOT EXISTS room_state (
  owner_credential_hash TEXT,
  tombstoned_at INTEGER,
  registry_floor INTEGER NOT NULL DEFAULT 0,
  ip_bucket_salt TEXT,
  created_at INTEGER
)`;

const SCHEMA_STATEMENTS = [
  // 里程碑事件日志：seq 由 DO 分配、房间内单调递增；
  // 不用 AUTOINCREMENT——seq 的分配要先过 epoch 闸，所以由 insertMilestone
  // 显式分配。seq 的来源是 room_meta 里的独立计数器（见下方 allocateSeq），
  // 不是「当前 events 表里的 MAX(seq)+1」（T4 修复轮 L1：MAX 查询会在未来加
  // 保留窗裁剪、删掉旧 events 行后往回掉，导致新分配的 seq 撞上/小于某个
  // 已经发给远端的旧 seq——那时候用一个与 events 行是否还在无关的独立计数器
  // 才不会跟着裁剪一起回退）。
  `CREATE TABLE IF NOT EXISTS events (
    seq     INTEGER PRIMARY KEY,
    epoch   INTEGER NOT NULL,
    session TEXT,
    kind    TEXT NOT NULL,
    ct      TEXT NOT NULL,
    n       TEXT NOT NULL,
    ts      INTEGER NOT NULL,
    client_msg_id TEXT
  )`,
  // 房间级零散状态（当前 epoch、房间 id、合法令牌集合……）——kv 形态，够用不过度设计。
  `CREATE TABLE IF NOT EXISTS room_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  )`,
  // input 通道暂存：仅桌面离线时才会有行；TTL 30 分钟；
  // 桌面回 input.ack 后删除；到期未 ack 则被动清除并回 input.expired。
  `CREATE TABLE IF NOT EXISTS pending_input (
    command_id TEXT PRIMARY KEY,
    session    TEXT,
    envelope   TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    subject    TEXT,
    generation INTEGER
  )`,
  // G8 三审 fix_required（codex xhigh 差量审）R3：deleteExpiredPendingInput
  // 现在每次 handleInput 入队前都会按 expires_at 查一遍——没有这条索引就是
  // 全表扫，守卫式迁移（CREATE INDEX IF NOT EXISTS 对新旧库都安全）。
  `CREATE INDEX IF NOT EXISTS idx_pending_input_expires ON pending_input(expires_at)`,
  // 配额计数器：按 UTC 年-月分桶。
  `CREATE TABLE IF NOT EXISTS quota_counters (
    period          TEXT PRIMARY KEY,
    milestone_count INTEGER NOT NULL DEFAULT 0
  )`,
  // 房间内 claim 尝试桶：固定一小时窗口，持久化以跨 DO 休眠。
  `CREATE TABLE IF NOT EXISTS claim_rate_limits (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    window_started_at INTEGER NOT NULL,
    attempts          INTEGER NOT NULL DEFAULT 0
  )`,
  // G8 R1（双路审 fix_required①·消息期限速）：input/control per-subject
  // 固定窗，结构照上面的 claim_rate_limits 同款姿势（持久化以跨 DO 休眠），
  // key 换成 (subject, channel) 联合主键——同一 subject 下无论开几个并发
  // socket，input/control 各自只有一行、共享同一份配额，不像先前误做成
  // attachment 版时那样一断线重连就清零。CREATE TABLE IF NOT EXISTS 对新旧
  // 房间的 DO 都安全（守卫式迁移，见 initSchema 头注释同款纪律）。
  `CREATE TABLE IF NOT EXISTS message_rate_limits (
    subject           TEXT NOT NULL,
    channel           TEXT NOT NULL CHECK (channel IN ('input','control')),
    window_started_at INTEGER NOT NULL,
    attempts          INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (subject, channel)
  )`,
  `CREATE TABLE IF NOT EXISTS token_subjects (
    subject TEXT PRIMARY KEY,
    generation INTEGER NOT NULL CHECK (generation > 0),
    state TEXT NOT NULL CHECK (state IN ('active','revoked')),
    scope TEXT CHECK (scope IN ('remote','pairing')),
    CHECK (state = 'revoked' OR scope IS NOT NULL)
  )`,
  `CREATE TABLE IF NOT EXISTS token_aliases (
    token_hash TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('current','prev')),
    generation INTEGER NOT NULL,
    access_expires INTEGER,
    valid_until INTEGER NOT NULL,
    UNIQUE (subject, kind)
  )`,
  `CREATE TABLE IF NOT EXISTS token_put_fingerprints (
    subject TEXT PRIMARY KEY,
    generation INTEGER NOT NULL CHECK (generation > 0),
    fingerprint TEXT NOT NULL CHECK (length(fingerprint) = 64)
  )`,
  // S1i2 §9.6 第 246 行：refresh 三帧成套的 relay 侧投递记账。一行 = 一个
  // 尚未投出回执的 in-flight 请求；投递谓词命中或 deadline 过期都会把行删掉
  // （见 room-do.js deliverRefreshReceipt）。connection_id 记的是「最近一次
  // 发来这个 request_id 的连接」——同 request_id 从新连接重发时安全重绑
  // （见 upsertRefreshRequest），不同 subject 一律拒绝，防 request_id 碰撞
  // 被用来劫持别的 subject 的待投递回执。
  // ip_bucket_key（S1i2 返工 R3·§9.8 第 263 行）：休眠唤醒后的 webSocketMessage
  // 拿不到原始 Request，消息期 per-IP 计费一律用建行时从 attachment 抄下来
  // 的这个 key，不现取 Request。列允许 NULL（legacy/直建行的测试路径不强制
  // 携带），但一旦有值必须是 deriveIpBucketKey 的定长输出（16 字节截断哈希
  // 的 hex = 32 字符）。
  `CREATE TABLE IF NOT EXISTS refresh_requests (
    request_id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    request_generation INTEGER NOT NULL CHECK (request_generation > 0),
    connection_id TEXT NOT NULL,
    deadline INTEGER NOT NULL,
    ip_bucket_key TEXT CHECK (ip_bucket_key IS NULL OR length(ip_bucket_key) = 32)
  )`,
  // R5.3：deadline 是 alarm 清扫与 nextRefreshRequestDeadline 排班的唯一查询
  // 键，加索引。
  `CREATE INDEX IF NOT EXISTS idx_refresh_requests_deadline ON refresh_requests(deadline)`,
  // S1i3 F1（§9.5 第 235 行·配对路由持久化）：单行表——subject 恒为 "pairing"，记「最近
  // 一次发来 pair.hello 的那条 remote 连接」的 connection_id。relay 转发 pair.hello /
  // pair.done 给桌面时在帧上盖章这个值（绝不信手机自报）；桌面回 pair.accept / pair.ready
  // 时凭这一行定向投递，不再 broadcastToRemotes 广播（同窗多手机不互收对方的 accept）。
  // 必须落库（不能只留内存 Map）：DO 休眠唤醒后内存态会丢，路由行还得在。
  `CREATE TABLE IF NOT EXISTS pairing_routes (
    subject TEXT PRIMARY KEY,
    connection_id TEXT NOT NULL
  )`,
];

export function hasTable(sql, tableName) {
  const rows = sql.exec("SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = ?", tableName);
  return rows.length > 0;
}

export function initRoomStateSentinel(sql, now = Date.now()) {
  sql.exec(ROOM_STATE_SCHEMA);
  ensureRoomStateIpBucketSaltColumn(sql);
  ensureRoomStateCreatedAtColumn(sql);
  sql.exec(
    "INSERT INTO room_state (owner_credential_hash, tombstoned_at, registry_floor, created_at) " +
      "SELECT NULL, NULL, 0, ? WHERE NOT EXISTS (SELECT 1 FROM room_state)",
    now
  );
  // SEC-3：存量房（预 SEC-3 部署）走上面的守卫式 ALTER 补出的 created_at 是
  // NULL——用「首次触碰」（这次构造）的时刻当起点回填，不去猜真实建房时刻
  // （旋转起点对回收截止的语义无损：只是让存量未认领房从这次部署起重新计
  // 满一个 UNCLAIMED_RECLAIM_MS 宽限窗，不会被追溯性地判定"早就到期"）。
  // 只影响 created_at 仍是 NULL 的那一行，之后再调用是空操作（幂等，同
  // ip_bucket_salt 迁移一族纪律）。
  sql.exec("UPDATE room_state SET created_at = ? WHERE created_at IS NULL", now);
}

// 守卫式迁移（同 ensureClientMsgIdColumn :783 姿势）：CREATE TABLE IF NOT
// EXISTS 对已存在的旧 room_state 是空操作，补不上这一列，单独 ALTER 一次；
// 新建的 room_state 已经带这列，这里会撞“列已存在”，用 try/catch 吞掉（其余
// 错误照常抛出）。
function ensureRoomStateIpBucketSaltColumn(sql) {
  try {
    sql.exec("ALTER TABLE room_state ADD COLUMN ip_bucket_salt TEXT");
  } catch (err) {
    const message = String((err && err.message) || err);
    if (!/duplicate column/i.test(message)) {
      throw err;
    }
  }
}

// SEC-3：同上，created_at 列的守卫式 ALTER——这条必须放进上面无条件跑的
// initRoomStateSentinel（构造器无条件调它，见 room-do.js 构造器注释），不能
// 只在"发现 room_state 不存在"时才跑，否则复刻 SEC-1 那个存量房被
// `!hasTable("room_state")` 挡住、列永远补不上的坑（见本单 brief「SEC-1 刚
// 踩的坑」）。
function ensureRoomStateCreatedAtColumn(sql) {
  try {
    sql.exec("ALTER TABLE room_state ADD COLUMN created_at INTEGER");
  } catch (err) {
    const message = String((err && err.message) || err);
    if (!/duplicate column/i.test(message)) {
      throw err;
    }
  }
}

export function getRoomState(sql) {
  const rows = sql.exec(
    "SELECT owner_credential_hash, tombstoned_at, registry_floor, created_at FROM room_state LIMIT 1"
  );
  return rows.length
    ? rows[0]
    : { owner_credential_hash: null, tombstoned_at: null, registry_floor: 0, created_at: null };
}

export function isRoomLive(sql) {
  return getRoomState(sql).tombstoned_at == null;
}

// ---- room_state.ip_bucket_salt（SEC-1：从 room_meta 迁来，恒存在的哨兵表
// 承载，鉴权前 deriveIpBucketKey 也能安全读写）----

export function getRoomIpBucketSalt(sql) {
  const rows = sql.exec("SELECT ip_bucket_salt FROM room_state LIMIT 1");
  return rows.length ? rows[0].ip_bucket_salt : null;
}

export function setRoomIpBucketSalt(sql, salt) {
  sql.exec("UPDATE room_state SET ip_bucket_salt = ?", salt);
}

export function withTransaction(sql, callback) {
  if (typeof sql.transactionSync !== "function") {
    throw new Error("SQL adapter does not provide transactionSync");
  }
  return sql.transactionSync(callback);
}

export function initSchema(sql) {
  for (const stmt of SCHEMA_STATEMENTS) {
    sql.exec(stmt);
  }
  // 守卫式迁移（v1.7.4）：已部署 DO 的旧 events 表没有 client_msg_id 列——
  // CREATE TABLE IF NOT EXISTS 对已存在的旧表是空操作，补不上这一列，所以单独
  // 跑一次 ALTER TABLE；新表在上面 CREATE TABLE 时已经带了这一列，这里会撞上
  // "列已存在"，用 try/catch 吞掉这一种错误（其余错误照常抛出，不悄悄吞真故
  // 障）。initSchema 本身可重复调用（幂等）——这个迁移步骤也一样可重入。
  ensureClientMsgIdColumn(sql);
  ensurePendingInputAuthorizationColumns(sql);
  // 先把旧行补成完整数据，再建唯一索引：这样首次迁移时建索引会对全部
  // client_msg_id 做一次最终完整性检查，而不是让 NULL 历史行暂时绕过索引。
  backfillLegacyClientMsgIds(sql);
  sql.exec(
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_events_client_msg_id ON events(client_msg_id) WHERE client_msg_id IS NOT NULL"
  );
  // S1ja F2（守卫式迁移·可重入）：__admin/register-token 后门连同它写的
  // room_meta['valid_tokens'] 行一并退役——只删路由/ADMIN_TOKEN 不清这一行的话，
  // 存量 dev token 仍能靠旧的 authorizeInboundSocket/canDeliverOutbound legacy
  // 豁免（下面两处已改 fail-closed）绕开整个注册表闸，且永不过期、不可吊销，
  // 是一条永久后门。DELETE 对不存在的行本就是空操作，天然幂等，不需要
  // try/catch 守卫。
  purgeLegacyValidTokensMeta(sql);
}

// SEC-1：业务 schema 延到鉴权成功后才建（room-do.js fetch() 鉴权枝汇流处 +
// alarm() 防御性兜底调用）。initSchema 全是 CREATE TABLE IF NOT EXISTS +
// 幂等 ALTER/backfill，本就可重入，这里只是给这个用途起一个更贴切的名字，
// 不是另一套逻辑。
export function ensureBusinessSchema(sql) {
  initSchema(sql);
}

// ---- 房间所有权、claim 桶与 tombstone ----

export function isClaimRateLimited(sql, now = Date.now()) {
  if (!hasTable(sql, "claim_rate_limits")) return false;
  const rows = sql.exec("SELECT window_started_at, attempts FROM claim_rate_limits WHERE id = 1");
  if (rows.length === 0) return false;
  const row = rows[0];
  return now < Number(row.window_started_at) + CLAIM_WINDOW_MS && Number(row.attempts) >= CLAIM_LIMIT;
}

// SEC-1：claim 路径（POST /room/<hex>/claim）只需要 room_state + 这一张小表，
// 不该拽起全部业务 schema——首行懒建，claim_rate_limits 结构照 SCHEMA_STATEMENTS
// 里那张一致（CREATE TABLE IF NOT EXISTS 幂等，重复调用安全）。
function recordClaimAttempt(sql, now) {
  sql.exec(`CREATE TABLE IF NOT EXISTS claim_rate_limits (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    window_started_at INTEGER NOT NULL,
    attempts          INTEGER NOT NULL DEFAULT 0
  )`);
  const rows = sql.exec("SELECT window_started_at, attempts FROM claim_rate_limits WHERE id = 1");
  if (rows.length === 0 || now >= Number(rows[0].window_started_at) + CLAIM_WINDOW_MS) {
    sql.exec(
      "INSERT INTO claim_rate_limits (id, window_started_at, attempts) VALUES (1, ?, 1) " +
        "ON CONFLICT(id) DO UPDATE SET window_started_at = excluded.window_started_at, attempts = 1",
      now
    );
    return;
  }
  sql.exec("UPDATE claim_rate_limits SET attempts = attempts + 1 WHERE id = 1");
}

export function claimRoom(sql, credentialHash, now = Date.now()) {
  return withTransaction(sql, () => {
    // edge 10/min 已在 Worker 层先行；事务内仍重查墓碑，防 body 读取期间
    // 房间被终结。DO 30/h 属业务桶，排在 410 后，且同哈希幂等重试不受它
    // 影响也不计数。
    const state = getRoomState(sql);
    if (state.tombstoned_at != null) return "tombstoned";
    if (state.owner_credential_hash === credentialHash) return "same";
    if (isClaimRateLimited(sql, now)) return "rate_limited";

    recordClaimAttempt(sql, now);
    if (state.owner_credential_hash != null) return "conflict";
    sql.exec(
      "UPDATE room_state SET owner_credential_hash = ? WHERE owner_credential_hash IS NULL",
      credentialHash
    );
    return "claimed";
  });
}

// G8 R1（双路审 fix_required①·消息期限速）：input/control per-subject 固定
// 窗——一次调用 = 一次尝试，返回是否放行 + 是否是本窗口第一次超限。
//
// 与上面 claimRoom 的 isClaimRateLimited/recordClaimAttempt 两段式（先只读
// 判断、再有条件写）不同，这里故意合成一步；但 attempts 的写法经过 G8
// 三审 fix_required（codex xhigh 差量审）R2 改过一轮——**首次超限那一次仍
// 要写库**（把 attempts 从 limit 推到 limit+1，这个精确的 limit+1 数值本身
// 就是"本窗口第一次超限"的信号，room-do.js 靠它决定要不要记一次协议违例，
// 见 G8 R3），但**从第二次超限起，attempts 饱和钉死在 limit+1，之后只读不
// 写**：读到的 attempts 已经 > limit，直接判拒绝、firstExceedThisWindow
// 恒 false，连 SQL 都不碰。旧版每次超限都无条件 UPDATE，等于攻击者靠疯狂
// 发送反正会被拒的帧就能白嫖无限次数据库写——这正好违反了 room-do.js 里
// G8 常量注释自己写的"别把乱发帧变成白嫖写"的原则（呼应 §6b 防打爆同一条
// 纪律，PROTOCOL_VIOLATION_LIMIT 头注释也是同一个道理）。
// 读-改-写之间无 await（同 allocateSeq 头注释的 L2 不变量），单个 JS 调用
// 内天然原子，不需要额外包一层事务。
export function takeMessageRateSlot(sql, { subject, channel, limit, windowMs, now }) {
  const rows = sql.exec(
    "SELECT window_started_at, attempts FROM message_rate_limits WHERE subject = ? AND channel = ?",
    subject, channel
  );
  const existing = rows.length ? rows[0] : null;
  const windowExpired = !existing || now >= Number(existing.window_started_at) + windowMs;

  if (windowExpired) {
    sql.exec(
      "INSERT INTO message_rate_limits (subject, channel, window_started_at, attempts) VALUES (?, ?, ?, 1) " +
        "ON CONFLICT(subject, channel) DO UPDATE SET window_started_at = excluded.window_started_at, attempts = 1",
      subject, channel, now
    );
    return { allowed: true, firstExceedThisWindow: false };
  }

  const priorAttempts = Number(existing.attempts);
  if (priorAttempts > limit) {
    // 已经饱和在 limit+1——本窗口不是第一次超限了，纯只读判断，绝不再写库。
    return { allowed: false, firstExceedThisWindow: false };
  }

  // priorAttempts <= limit：要么仍在预算内（这次写完还 <= limit，放行），
  // 要么正是把配额从 limit 推过 limit+1 的那一次（这次写完 > limit，是本
  // 窗口第一次超限）——两种情况都需要真的写一次库；写完之后 attempts 永远
  // 不会超过 limit+1，因为超过 limit 的调用从上面的分支直接返回，不会再
  // 落到这里继续递增。
  const nextAttempts = priorAttempts + 1;
  sql.exec(
    "UPDATE message_rate_limits SET attempts = ? WHERE subject = ? AND channel = ?",
    nextAttempts, subject, channel
  );
  return { allowed: nextAttempts <= limit, firstExceedThisWindow: nextAttempts === limit + 1 };
}

export function tombstoneRoom(sql, now = Date.now()) {
  return withTransaction(sql, () => {
    if (!isRoomLive(sql)) return false;
    const tables = sql.exec(
      "SELECT name FROM sqlite_master " +
        "WHERE type = 'table' AND name <> 'room_state' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    );
    for (const { name } of tables) {
      // name 来自 sqlite_master 而非请求；双引号仍做完整 escaping，防未来业务
      // 表名含特殊字符时 purge 漂移。room_state 是唯一保留表。
      sql.exec(`DELETE FROM "${String(name).replaceAll('"', '""')}"`);
    }
    // room_state 是唯一不被 purge 触碰的真相；墓碑必须是事务最后一条写。
    sql.exec("UPDATE room_state SET tombstoned_at = ?", now);
    return true;
  });
}

// ---- 正式令牌注册表（§9.2） ----

export function clampTokenExpiry(cap, inputMs, relayNow = Date.now()) {
  const capMs = TOKEN_TTL_CAPS_MS[cap];
  if (capMs == null) throw new TypeError(`unknown token TTL cap: ${cap}`);
  if (Number.isInteger(inputMs) && inputMs > Number.MAX_SAFE_INTEGER) {
    throw new TypeError("token expiry exceeds JSON safe integer");
  }
  if (Number.isSafeInteger(inputMs) && inputMs <= 0) {
    throw new TypeError("token expiry must be positive");
  }
  if (!Number.isSafeInteger(inputMs)) throw new TypeError("invalid token expiry timestamp");
  if (inputMs < 1_000_000_000_000) {
    throw new TypeError("token expiry must use unix milliseconds");
  }
  if (!Number.isSafeInteger(relayNow) || relayNow <= 0) {
    throw new TypeError("relayNow must be a positive JSON-safe unix millisecond timestamp");
  }
  return Math.min(inputMs, relayNow + capMs + TOKEN_TTL_SKEW_MS);
}

function assertTokenSubject(subject, scope, state) {
  if (subject !== "pairing" && !DEVICE_SUBJECT_RE.test(subject || "")) {
    throw new TypeError("invalid token subject");
  }
  if (!["active", "revoked"].includes(state)) throw new TypeError("invalid token subject state");
  if (scope != null && !["remote", "pairing"].includes(scope)) throw new TypeError("invalid token scope");
  if (state === "active" && scope == null) throw new TypeError("active token subject requires scope");
  if (scope != null && subject === "pairing" && scope !== "pairing") {
    throw new TypeError("pairing subject requires pairing scope");
  }
  if (scope != null && subject !== "pairing" && scope === "pairing") {
    throw new TypeError("device subject cannot use pairing scope");
  }
}

function normalizeTokenAlias(alias, subject, subjectScope, relayNow) {
  if (!TOKEN_HASH_RE.test(alias?.token_hash || "")) throw new TypeError("invalid token hash");
  if (!["current", "prev"].includes(alias.kind)) throw new TypeError("invalid token alias kind");
  if (!Number.isSafeInteger(alias.generation) || alias.generation <= 0) {
    throw new TypeError("invalid token alias generation");
  }
  if (subjectScope === "pairing" && alias.kind !== "current") {
    throw new TypeError("pairing subject only supports a current alias");
  }

  if (alias.kind === "current") {
    const cap = subject === "pairing" ? "pairing" : "access";
    const accessExpires = clampTokenExpiry(cap, alias.access_expires, relayNow);
    const validUntil = subject === "pairing"
      ? accessExpires
      : clampTokenExpiry("refresh_until", alias.valid_until, relayNow);
    if (accessExpires > validUntil) throw new TypeError("access_expires must not exceed valid_until");
    return { ...alias, access_expires: accessExpires, valid_until: validUntil };
  }

  return {
    ...alias,
    access_expires: null,
    valid_until: clampTokenExpiry("prev", alias.valid_until, relayNow),
  };
}

/**
 * 测试种行与 S1e token.put 共用的唯一写入口。它执行 §9.2 的 grammar、时间
 * 单位/上限/字段关系校验，并在单事务内重建该 subject 的 alias 集合。
 */
export function putTokenRegistryEntry(sql, entry, relayNow = Date.now(), options = {}) {
  return withTransaction(sql, () =>
    putTokenRegistryEntryInTransaction(sql, entry, relayNow, options)
  );
}

/**
 * 与 putTokenRegistryEntry 完全相同的 CAS/fingerprint 写语义，但调用方必须已
 * 持有事务。sync/reset 用它把整批对账保持在一个 SQL 事务内，普通 token.put
 * 仍由上面的兼容入口负责开启事务。
 */
export function putTokenRegistryEntryInTransaction(sql, entry, relayNow = Date.now(), options = {}) {
  const normalized = normalizeTokenRegistryEntry(entry, relayNow);
  const putFingerprint = fingerprintNormalizedOriginalPut(entry, normalized);
  if (options.cas === true) {
    const currentRows = sql.exec(
      "SELECT subject, generation, state, scope FROM token_subjects WHERE subject = ? LIMIT 1",
      normalized.subject
    );
    const current = currentRows.length ? currentRows[0] : null;
    const floor = Number(getRoomState(sql).registry_floor);
    if (normalized.generation <= floor) {
      return { result: "rejected", reason: "generation_at_or_below_floor" };
    }
    if (current && normalized.generation < Number(current.generation)) {
      return { result: "rejected", reason: "generation_too_low" };
    }
    if (current && normalized.generation === Number(current.generation)) {
      const idempotent = putFingerprint == null
        ? tokenRegistryEntryEquals(sql, normalized, current)
        : tokenPutFingerprintEquals(sql, normalized.subject, normalized.generation, putFingerprint);
      return idempotent
        ? { result: "idempotent", entry: normalized }
        : { result: "rejected", reason: "generation_content_mismatch" };
    }
  }

  writeNormalizedTokenRegistryEntry(sql, normalized, putFingerprint);
  return options.cas === true ? { result: "ok", entry: normalized } : normalized;
}

export function reconcileTokenRegistry(sql, { revision, entries, reset = false }, relayNow = Date.now()) {
  return withTransaction(sql, () => {
    let floor = Number(getRoomState(sql).registry_floor);
    const revokedSubjects = [];
    if (reset) {
      revokedSubjects.push(...sql.exec("SELECT subject FROM token_subjects").map((row) => row.subject));
      const tableHighWater = tokenRegistryTableHighWater(sql);
      floor = Math.max(floor, tableHighWater);
      sql.exec("UPDATE room_state SET registry_floor = ?", floor);
      clearTokenRegistryInTransaction(sql);
    }

    const listedSubjects = new Set();
    const results = [];
    for (const entry of entries) {
      if (typeof entry?.subject === "string") listedSubjects.add(entry.subject);
      try {
        if (entry?.invalid === true) throw new TypeError("invalid sync entry");
        results.push(putTokenRegistryEntryInTransaction(sql, entry, relayNow, { cas: true }));
      } catch (error) {
        if (!(error instanceof TypeError) && !/token hash already belongs to another subject/.test(String(error?.message))) {
          throw error;
        }
        // 与单帧 put 一致：格式/碰撞是该条 rejected；reset/sync 的其它条目与
        // 最终 ack 继续，不把一个坏条目升级成整帧回滚。
        results.push({ result: "rejected", error });
      }
    }

    if (!reset) {
      const current = sql.exec("SELECT subject, generation, state FROM token_subjects");
      for (const row of current) {
        if (listedSubjects.has(row.subject) || row.state === "revoked" || Number(row.generation) >= revision) {
          continue;
        }
        sql.exec(
          "UPDATE token_subjects SET generation = ?, state = 'revoked', scope = NULL WHERE subject = ?",
          revision,
          row.subject
        );
        sql.exec("DELETE FROM token_aliases WHERE subject = ?", row.subject);
        sql.exec("DELETE FROM token_put_fingerprints WHERE subject = ?", row.subject);
        revokedSubjects.push(row.subject);
      }
    }

    const relayHighWater = Math.max(tokenRegistryTableHighWater(sql), floor, revision);
    return { results, revokedSubjects, relayHighWater };
  });
}

function tokenRegistryTableHighWater(sql) {
  const rows = sql.exec("SELECT COALESCE(MAX(generation), 0) AS high_water FROM token_subjects");
  return rows.length ? Number(rows[0].high_water) : 0;
}

function normalizeTokenRegistryEntry(entry, relayNow = Date.now()) {
  const state = entry?.state ?? "active";
  const scope = entry?.scope ?? null;
  assertTokenSubject(entry?.subject, scope, state);
  if (Number.isSafeInteger(entry?.generation) && entry.generation <= 0) {
    throw new TypeError("token subject generation must be positive");
  }
  if (!Number.isSafeInteger(entry?.generation)) {
    throw new TypeError("invalid token subject generation");
  }
  const aliases = (entry.aliases ?? []).map((alias) =>
    normalizeTokenAlias(alias, entry.subject, scope, relayNow)
  );
  if (aliases.length > 2 || new Set(aliases.map((alias) => alias.kind)).size !== aliases.length) {
    throw new TypeError("token subject aliases must have unique current/prev kinds");
  }
  if (state === "revoked" && aliases.length > 0) {
    throw new TypeError("revoked token subject cannot retain aliases");
  }
  const current = aliases.find((alias) => alias.kind === "current");
  const prev = aliases.find((alias) => alias.kind === "prev");
  if (current && prev) {
    // §9.2: prev=min(prev_expires, refresh_until)。两项都先各自过 cap，再用
    // current.valid_until（即 refresh_until）封住旧令牌的最长追赶窗。
    prev.valid_until = Math.min(prev.valid_until, current.valid_until);
  }
  return { subject: entry.subject, generation: entry.generation, state, scope, aliases };
}

function writeNormalizedTokenRegistryEntry(sql, entry, putFingerprint) {
  for (const alias of entry.aliases) {
    const collision = sql.exec(
      "SELECT subject FROM token_aliases WHERE token_hash = ? AND subject <> ? LIMIT 1",
      alias.token_hash,
      entry.subject
    );
    if (collision.length > 0) throw new Error("token hash already belongs to another subject");
  }
  sql.exec(
    "INSERT INTO token_subjects (subject, generation, state, scope) VALUES (?, ?, ?, ?) " +
      "ON CONFLICT(subject) DO UPDATE SET generation=excluded.generation, state=excluded.state, scope=excluded.scope",
    entry.subject,
    entry.generation,
    entry.state,
    entry.scope
  );
  sql.exec("DELETE FROM token_aliases WHERE subject = ?", entry.subject);
  for (const alias of entry.aliases) {
    sql.exec(
      "INSERT INTO token_aliases " +
        "(token_hash, subject, kind, generation, access_expires, valid_until) VALUES (?, ?, ?, ?, ?, ?)",
      alias.token_hash,
      entry.subject,
      alias.kind,
      alias.generation,
      alias.access_expires,
      alias.valid_until
    );
  }
  if (putFingerprint == null) {
    sql.exec("DELETE FROM token_put_fingerprints WHERE subject = ?", entry.subject);
  } else {
    sql.exec(
      "INSERT INTO token_put_fingerprints (subject, generation, fingerprint) VALUES (?, ?, ?) " +
        "ON CONFLICT(subject) DO UPDATE SET generation=excluded.generation, fingerprint=excluded.fingerprint",
      entry.subject,
      entry.generation,
      putFingerprint
    );
  }
}

function fingerprintNormalizedOriginalPut(rawEntry, normalized) {
  if (normalized.state !== "active") return null;
  const current = (rawEntry.aliases ?? []).find((alias) => alias.kind === "current");
  if (!current) return null;
  const prev = (rawEntry.aliases ?? []).find((alias) => alias.kind === "prev");
  const canonical = {
    subject: normalized.subject,
    generation: normalized.generation,
    scope: normalized.scope,
    current: normalized.scope === "pairing"
      ? {
          token_hash: current.token_hash,
          access_expires: current.access_expires,
        }
      : {
          token_hash: current.token_hash,
          access_expires: current.access_expires,
          refresh_until: current.valid_until,
        },
  };
  if (prev) {
    canonical.prev = {
      token_hash: prev.token_hash,
      generation: prev.generation,
      prev_expires: prev.valid_until,
    };
  }
  return createHash("sha256").update(JSON.stringify(canonical), "utf8").digest("hex");
}

function tokenPutFingerprintEquals(sql, subject, generation, fingerprint) {
  const rows = sql.exec(
    "SELECT generation, fingerprint FROM token_put_fingerprints WHERE subject = ? LIMIT 1",
    subject
  );
  return rows.length === 1 &&
    Number(rows[0].generation) === generation &&
    rows[0].fingerprint === fingerprint;
}

function tokenRegistryEntryEquals(sql, expected, current) {
  if (current.subject !== expected.subject ||
      Number(current.generation) !== expected.generation ||
      current.state !== expected.state ||
      current.scope !== expected.scope) {
    return false;
  }
  const aliases = sql.exec(
    "SELECT token_hash, kind, generation, access_expires, valid_until " +
      "FROM token_aliases WHERE subject = ? ORDER BY kind",
    expected.subject
  );
  const wanted = [...expected.aliases].sort((left, right) => left.kind.localeCompare(right.kind));
  if (aliases.length !== wanted.length) return false;
  return aliases.every((alias, index) => {
    const other = wanted[index];
    return alias.token_hash === other.token_hash &&
      alias.kind === other.kind &&
      Number(alias.generation) === other.generation &&
      (alias.access_expires == null ? null : Number(alias.access_expires)) === other.access_expires &&
      Number(alias.valid_until) === other.valid_until;
  });
}

export function clearTokenRegistry(sql) {
  return withTransaction(sql, () => clearTokenRegistryInTransaction(sql));
}

function clearTokenRegistryInTransaction(sql) {
  sql.exec("DELETE FROM token_put_fingerprints");
  sql.exec("DELETE FROM token_aliases");
  sql.exec("DELETE FROM token_subjects");
}

export function getTokenSubject(sql, subject) {
  const rows = sql.exec(
    "SELECT subject, generation, state, scope FROM token_subjects WHERE subject = ? LIMIT 1",
    subject
  );
  return rows.length ? rows[0] : null;
}

export function getTokenAlias(sql, subject, kind) {
  const rows = sql.exec(
    "SELECT token_hash, subject, kind, generation, access_expires, valid_until " +
      "FROM token_aliases WHERE subject = ? AND kind = ? LIMIT 1",
    subject,
    kind
  );
  return rows.length ? rows[0] : null;
}

export function resolveTokenAdmission(sql, tokenHash, now = Date.now()) {
  // SEC-1：remote 打空 schema 房（业务 schema 还没建）时 token_aliases/
  // token_subjects 不存在——照 isClaimRateLimited(:216) 的 hasTable 守卫先例，
  // 打不中就是干净 401，不建表、不抛 SQL 异常。
  if (!hasTable(sql, "token_aliases") || !hasTable(sql, "token_subjects")) return null;
  if (!TOKEN_HASH_RE.test(tokenHash || "")) return null;
  const rows = sql.exec(
    "SELECT a.token_hash, a.subject, a.kind, a.generation, a.access_expires, a.valid_until, " +
      "s.generation AS subject_generation, s.state AS subject_state, s.scope " +
      "FROM token_aliases a JOIN token_subjects s ON s.subject = a.subject " +
      "WHERE a.token_hash = ? LIMIT 1",
    tokenHash
  );
  if (rows.length === 0) return null;
  const row = rows[0];
  if (row.subject_state !== "active") return null;
  if (row.kind === "current" && Number(row.generation) !== Number(row.subject_generation)) return null;

  let admittedScope = null;
  if (row.kind === "current" && now < Number(row.access_expires)) admittedScope = row.scope;
  else if (row.kind === "current" && now < Number(row.valid_until) && row.scope !== "pairing") admittedScope = "refresh";
  else if (row.kind === "prev" && now < Number(row.valid_until)) admittedScope = "refresh";
  if (!admittedScope) return null;
  return {
    scope: admittedScope,
    subject: row.subject,
    kind: row.kind,
    generation: Number(row.subject_generation),
    alias_generation: Number(row.generation),
    access_expires: row.access_expires == null ? null : Number(row.access_expires),
    valid_until: Number(row.valid_until),
  };
}

// ---- refresh_requests（§9.6 第 246 行·relay 侧投递记账） ----

/**
 * 手机 token.refresh 到达时落盘/续盘一行。同 request_id 从新连接重发 → 核
 * 同 subject 后安全重绑 connection_id/request_generation/deadline/
 * ip_bucket_key（重发可能换了连接、换了 IP，行要跟着抄最新那次的）；不同
 * subject 一律拒绝（防 request_id 碰撞劫持别的 subject 的待投递回执）。
 * @returns {{ok:true}|{ok:false, reason:"refresh_request_subject_conflict"}}
 */
export function upsertRefreshRequest(sql, { requestId, subject, requestGeneration, connectionId, deadline, ipBucketKey = null }) {
  return withTransaction(sql, () => {
    const existing = sql.exec(
      "SELECT subject FROM refresh_requests WHERE request_id = ? LIMIT 1",
      requestId
    );
    if (existing.length > 0 && existing[0].subject !== subject) {
      return { ok: false, reason: "refresh_request_subject_conflict" };
    }
    sql.exec(
      "INSERT INTO refresh_requests (request_id, subject, request_generation, connection_id, deadline, ip_bucket_key) " +
        "VALUES (?, ?, ?, ?, ?, ?) " +
        "ON CONFLICT(request_id) DO UPDATE SET " +
        "request_generation = excluded.request_generation, " +
        "connection_id = excluded.connection_id, " +
        "deadline = excluded.deadline, " +
        "ip_bucket_key = excluded.ip_bucket_key",
      requestId,
      subject,
      requestGeneration,
      connectionId,
      deadline,
      ipBucketKey
    );
    return { ok: true };
  });
}

export function getRefreshRequest(sql, requestId) {
  const rows = sql.exec(
    "SELECT request_id, subject, request_generation, connection_id, deadline, ip_bucket_key " +
      "FROM refresh_requests WHERE request_id = ? LIMIT 1",
    requestId
  );
  return rows.length ? rows[0] : null;
}

export function deleteRefreshRequest(sql, requestId) {
  sql.exec("DELETE FROM refresh_requests WHERE request_id = ?", requestId);
}

// R1（§9.6 第 249 行·v1.8.5）：过期是真删行，不是查询时过滤——
// nextRefreshRequestDeadline 只在 SELECT 里过滤 deadline>now，行本身若从不
// 被删会一直滞留：① alarm 排班对它空转（醒来什么也不做）；② 回执从未到达
// 的行永久占用；③ 滞留行让 isResend 对该 request_id 永久为真，从此免疫
// §9.8 6/min 主桶（真实滥用面）。alarm() 每次醒来都调这个函数扫一遍。
export function deleteExpiredRefreshRequests(sql, now) {
  sql.exec("DELETE FROM refresh_requests WHERE deadline <= ?", now);
}

// P2-3：scheduleNextTokenAlarm 的候选之一——只看未来（deadline > now）的行，
// 已过期的行不该把 alarm 钉在过去、造成到点后立刻又拿同一个过期时刻重新
// setAlarm 的空转循环。
// SEC-3：hasTable 守卫（同 isClaimRateLimited/resolveTokenAdmission 先例）——
// scheduleNextTokenAlarm 现在也从 fetch() 鉴权/业务 schema 建立**之前**的新
// 触发点（未认领房的 claim POST / 失败 upgrade）调用，那条路径上
// refresh_requests 所在的 11 张业务表可能压根还没建；打不中就当没有候选，
// 不建表、不抛 SQL 异常。
export function nextRefreshRequestDeadline(sql, now) {
  if (!hasTable(sql, "refresh_requests")) return null;
  const rows = sql.exec("SELECT MIN(deadline) AS next FROM refresh_requests WHERE deadline > ?", now);
  const value = rows.length ? rows[0].next : null;
  return value == null ? null : Number(value);
}

// ---- pairing_routes（S1i3 F1·§9.5 第 235 行·relay 侧配对路由持久化） ----

/**
 * pair.hello / pair.done 转发时都要 upsert（S1i3 F1 返工·§9.5 第 235 行两种帧字面都要
 * 「持久写入」）：subject 恒为 "pairing"，值是发起/完成这轮配对的那条 remote 连接的
 * connection_id（relay 自己认定的，不信手机自报）。单行表，天然覆盖上一轮配对留下的路由。
 * done 也要写，不能只信 hello 时写好的那一行还在指着正确的连接——手机可能在 accept→ready
 * 窗口掉线重连（重连后 connection_id 是新随机值），也可能同窗第二台手机的 hello 抢先搬走
 * 了路由；两种情况都要靠 done 重新把路由行写回真正发出这条 done 的连接，否则 ready 会投
 * 空或投错（详见 room-do.js 对 pair.done 分支的注释）。唯一写口是 room-do.js 的
 * recordPairingRoute()，调用前会先判 assertRoomLive()。
 */
export function setPairingRoute(sql, connectionId) {
  sql.exec(
    "INSERT INTO pairing_routes (subject, connection_id) VALUES ('pairing', ?) " +
      "ON CONFLICT(subject) DO UPDATE SET connection_id = excluded.connection_id",
    connectionId
  );
}

/**
 * pair.accept / pair.ready 定向投递时读：返回最近一次 pair.hello 记下的 connection_id，
 * 没有任何配对进行过时返回 null（room-do.js 的调用方据此安全丢弃，不是错误）。
 */
export function getPairingRoute(sql) {
  const rows = sql.exec(
    "SELECT connection_id FROM pairing_routes WHERE subject = 'pairing' LIMIT 1"
  );
  return rows.length ? rows[0].connection_id : null;
}

function ensureClientMsgIdColumn(sql) {
  try {
    sql.exec("ALTER TABLE events ADD COLUMN client_msg_id TEXT");
  } catch (err) {
    const message = String((err && err.message) || err);
    if (!/duplicate column/i.test(message)) {
      throw err;
    }
  }
}

function ensurePendingInputAuthorizationColumns(sql) {
  const columns = new Set(sql.exec("PRAGMA table_info(pending_input)").map((row) => row.name));
  if (!columns.has("subject")) sql.exec("ALTER TABLE pending_input ADD COLUMN subject TEXT");
  if (!columns.has("generation")) sql.exec("ALTER TABLE pending_input ADD COLUMN generation INTEGER");
}

// S1ja F2：清掉后门写过的 room_meta['valid_tokens'] 行——DELETE 对不存在的键
// 本就是空操作，天然幂等，不需要 ensureClientMsgIdColumn 那种 try/catch 守卫。
function purgeLegacyValidTokensMeta(sql) {
  sql.exec("DELETE FROM room_meta WHERE key = 'valid_tokens'");
}

// 标准 UUIDv5（RFC 4122，命名空间 + SHA-1）。算法与
// test/client-msg-id-derivation.test.js 的独立参考实现一致，命名空间也复用
// 仓库统一常量；这里仅供 relay 私有的 legacy 回填，不参与跨端派生 KAT。
function uuidv5(name, namespaceUuid) {
  const nsBytes = Buffer.from(namespaceUuid.replace(/-/g, ""), "hex");
  const nameBytes = Buffer.from(name, "utf8");
  const hash = createHash("sha1").update(Buffer.concat([nsBytes, nameBytes])).digest();
  const bytes = Buffer.from(hash.subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x50; // version 5
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // RFC4122 variant
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function backfillLegacyClientMsgIds(sql) {
  const rows = sql.exec("SELECT seq FROM events WHERE client_msg_id IS NULL ORDER BY seq ASC");
  if (rows.length === 0) return;

  // 生产路径中，能留下旧 events 的房间必然已在更早一次通过鉴权的 fetch 里
  // ensureRoomId；room_meta 与 events 同属该 DO 的持久 SQLite，重启/部署后仍在。
  // 空串只为手工损坏/非生产旧库兜底，seq 仍保证单个 DO 内生成值互不相同。
  const roomId = getMeta(sql, "room_id", "");
  for (const row of rows) {
    const clientMsgId = uuidv5(`legacy|${roomId}|${String(row.seq)}`, CLIENT_MSG_ID_NAMESPACE);
    sql.exec("UPDATE events SET client_msg_id = ? WHERE seq = ?", clientMsgId, row.seq);
  }
}

// ---- room_meta（kv） ----

export function getMeta(sql, key, fallback = null) {
  const rows = sql.exec("SELECT value FROM room_meta WHERE key = ?", key);
  return rows.length ? rows[0].value : fallback;
}

export function setMeta(sql, key, value) {
  sql.exec(
    "INSERT INTO room_meta (key, value) VALUES (?, ?) " +
      "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    key,
    String(value)
  );
}

export function ensureRoomId(sql, roomId) {
  const existing = getMeta(sql, "room_id");
  if (!existing) {
    setMeta(sql, "room_id", roomId);
    return roomId;
  }
  return existing;
}

// ---- epoch（防双写） ----

export function getCurrentEpoch(sql) {
  return Number(getMeta(sql, "current_epoch", "0"));
}

// 桌面每次连上来，relay 把房间 epoch +1；旧 epoch 的写入此后一律被拒。
export function bumpEpoch(sql) {
  const next = getCurrentEpoch(sql) + 1;
  setMeta(sql, "current_epoch", next);
  return next;
}

// ---- 里程碑事件（events）+ seq 计数器 ----

// seq 的权威来源 = room_meta 里的独立计数器（key "seq_counter"），不是
// events 表的 MAX(seq)（T4 修复轮 L1，理由见上方 SCHEMA_STATEMENTS 注释）。
// 语义仍是「这个房间目前已分配到的最大 seq」，对外行为不变——只是存储从
// 「查询算出来」变成「读一个持久计数器」。
export function headSeq(sql) {
  return Number(getMeta(sql, "seq_counter", "0"));
}

// 【L2 不变量】allocateSeq 从「读计数器」到「写回 +1」之间绝不能插入任何
// await：Cloudflare DO 的 ctx.storage.sql 是同步 API，本文件所有函数也都
// 保持全同步，这段代码天然满足「读-改-写」不可被打断；未来谁要把这段改成
// 异步（比如中间插一次网络调用），必须先想清楚怎么保这段的原子性，否则
// 两个并发调用可能读到同一个旧值、分配出重复的 seq。
function allocateSeq(sql) {
  const next = headSeq(sql) + 1;
  setMeta(sql, "seq_counter", next);
  return next;
}

/**
 * 插入一条里程碑事件；seq 由本函数分配（房间级单调计数器 +1，见 allocateSeq）。
 * 若传入的 epoch 落后于房间当前 epoch，拒绝写入（防双写）——注意这个拒绝
 * 发生在分配 seq 之前，被拒的写入不会消耗一个 seq 号。
 * @returns {{ok:true, seq:number}|{ok:true, seq:number, dedup:true}|{ok:false, reason:"stale_epoch", currentEpoch:number}}
 */
export function insertMilestone(sql, { epoch, session, kind, ct, n, ts, client_msg_id = null }) {
  const currentEpoch = getCurrentEpoch(sql);
  if (epoch < currentEpoch) {
    return { ok: false, reason: "stale_epoch", currentEpoch };
  }

  // client_msg_id 去重：命中已存在的行 → 幂等成功，返回既有
  // seq，不消耗新 seq、不重插。DO 内所有 sql.exec 调用天然单线程串行（同 L2
  // 不变量），这里"先查后插"不需要额外加锁。
  if (client_msg_id) {
    const existing = sql.exec("SELECT seq FROM events WHERE client_msg_id = ?", client_msg_id);
    if (existing.length > 0) {
      return { ok: true, seq: existing[0].seq, dedup: true };
    }
  }

  const seq = allocateSeq(sql);
  sql.exec(
    "INSERT INTO events (seq, epoch, session, kind, ct, n, ts, client_msg_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    seq,
    epoch,
    session ?? null,
    kind,
    ct,
    n,
    ts,
    client_msg_id ?? null
  );
  return { ok: true, seq };
}

// 重连补发：lastSeq 之后的里程碑，按 seq 升序。
export function replaySince(sql, lastSeq) {
  const n = Number(lastSeq) || 0;
  return sql.exec(
    "SELECT seq, epoch, session, kind, ct, n, ts, client_msg_id FROM events WHERE seq > ? ORDER BY seq ASC",
    n
  );
}

// ---- input 暂存队列 ----

const DEFAULT_INPUT_TTL_MS = 30 * 60 * 1000; // 30 分钟

export function enqueueInput(sql, {
  commandId,
  session,
  envelopeJson,
  now,
  subject = null,
  generation = null,
  ttlMs = DEFAULT_INPUT_TTL_MS,
}) {
  sql.exec(
    "INSERT INTO pending_input " +
      "(command_id, session, envelope, created_at, expires_at, subject, generation) VALUES (?, ?, ?, ?, ?, ?, ?) " +
      "ON CONFLICT(command_id) DO NOTHING",
    commandId,
    session ?? null,
    envelopeJson,
    now,
    now + ttlMs,
    subject,
    generation
  );
}

/**
 * 按 created_at 升序（FIFO）取出所有暂存 input，划分成「仍在 TTL 内可投递」
 * 与「已过期该丢弃」两组。调用方负责：把 expired 逐条 removePendingInput +
 * 回执 input.expired；把 deliverable 逐条送给刚上线的桌面连接。
 */
export function drainDeliverableInput(sql, now) {
  const rows = sql.exec("SELECT * FROM pending_input ORDER BY created_at ASC, rowid ASC");
  const deliverable = [];
  const expired = [];
  for (const row of rows) {
    if (row.expires_at < now) {
      expired.push(row);
    } else {
      deliverable.push(row);
    }
  }
  return { deliverable, expired };
}

// G8 三审 fix_required（codex xhigh 差量审）R3：handleInput 每次入队前都要
// 先清一遍过期行（见 room-do.js purgeExpiredPendingInput），这条路径现在是
// 高频路径（每条 offline input 都要过一次），不能沿用 drainDeliverableInput
// 那套「SELECT * ... 把整张表（含可能接近 4MB 的 envelope 大字段）搬进 JS」
// 的做法——drainDeliverableInput 服务的是桌面刚上线、本来就要把全部暂存
// input 的完整内容转发出去那条低频路径，两条路径的读取代价该分开算，不能
// 因为这条新路径而牵连旧路径也去读一份用不上的大字段（drainDeliverableInput
// 本身不动）。这里只按 expires_at 索引查 command_id，全程不碰 envelope 列；
// SELECT 和 DELETE 用同一个 `expires_at < now` 谓词，单线程同步无 await
// 保证两条语句之间没有任何其它写入插进来，命中的行集合逐字节相同，等价于
// 「先选出这批 id，再按这批 id 批量删」。
export function deleteExpiredPendingInput(sql, now) {
  const rows = sql.exec("SELECT command_id FROM pending_input WHERE expires_at < ?", now);
  const commandIds = rows.map((row) => row.command_id);
  if (commandIds.length > 0) {
    sql.exec("DELETE FROM pending_input WHERE expires_at < ?", now);
  }
  return commandIds;
}

export function isPendingInputAuthorized(sql, row) {
  if (typeof row?.subject !== "string") return false;
  // S1i2 批次审 3③：generation 为 NULL 的行必须显式 fail-closed。旧实现靠
  // Number(null) === 0 与 token_subjects.generation 恒 > 0（schema CHECK）的
  // 算术巧合兜住同一个结果——两处任一天变了（比如未来 CHECK 放宽），巧合
  // 就会悄悄失效；这里把「没有 generation 就不算数」写成看得见的分支。
  if (row?.generation === null || row?.generation === undefined) return false;
  if (!Number.isSafeInteger(Number(row.generation))) return false;
  const subject = getTokenSubject(sql, row.subject);
  return subject?.state === "active" && Number(row.generation) === Number(subject.generation);
}

export function removePendingInput(sql, commandId) {
  sql.exec("DELETE FROM pending_input WHERE command_id = ?", commandId);
}

// G8 R4（双路审 fix_required④·消息期限速）：入队前先判该 command_id 是否
// 已在 pending_input——已在时按幂等语义直接放行，不重插也不拒。
// enqueueInput 本身走 ON CONFLICT(command_id) DO NOTHING，所以就算不做这个
// 判断、直接闯过容量闸再插一次也不会产生第二行；但如果队列刚好满员，
// 容量闸会在到达 enqueueInput 之前就先拦下这次重试、回一个名不副实的
// queue_full——这个函数让调用方能在容量判断之前先甄别「这其实是已经成功
// 过的同一条重试」，把它从容量判断里摘出来。
export function hasPendingInputCommandId(sql, commandId) {
  const rows = sql.exec("SELECT 1 AS present FROM pending_input WHERE command_id = ? LIMIT 1", commandId);
  return rows.length > 0;
}

// G8（C1 设计 v0.5 §8·消息期限速）：入队前查该房现存 pending_input 行数与
// 总字节，供 room-do.js handleInput 判断是否超过 PENDING_INPUT_ROW_LIMIT /
// PENDING_INPUT_BYTE_LIMIT。单 DO = 单房，pending_input 表本就是这一个房间
// 的暂存队列，不需要按 room 过滤。字节数用 LENGTH(CAST(envelope AS BLOB))
// 而不是裸 LENGTH(envelope)——SQLite 对 TEXT 列的 LENGTH() 返回的是字符数，
// envelope 里携带的密文/session 字段若出现非 ASCII 字符会导致字符数少算于
// 真实 UTF-8 字节数；CAST AS BLOB 才是按字节算，与 room-do.js 别处
// TextEncoder 字节口径一致（同 command_id/session 的 128 字节上限口径）。
export function pendingInputStats(sql) {
  const rows = sql.exec(
    "SELECT COUNT(*) AS row_count, COALESCE(SUM(LENGTH(CAST(envelope AS BLOB))), 0) AS total_bytes " +
      "FROM pending_input"
  );
  const row = rows.length ? rows[0] : { row_count: 0, total_bytes: 0 };
  return { rowCount: Number(row.row_count), totalBytes: Number(row.total_bytes) };
}

// ---- 配额计数器 ----

export function getQuotaCount(sql, period) {
  const rows = sql.exec("SELECT milestone_count FROM quota_counters WHERE period = ?", period);
  return rows.length ? Number(rows[0].milestone_count) : 0;
}

export function incrementQuotaCount(sql, period, by = 1) {
  sql.exec(
    "INSERT INTO quota_counters (period, milestone_count) VALUES (?, ?) " +
      "ON CONFLICT(period) DO UPDATE SET milestone_count = milestone_count + excluded.milestone_count",
    period,
    by
  );
}
