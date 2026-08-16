"use strict";
// room-do.js — S2 房间 DO：一个 Durable Object = 一个房间。
//
// 用 Hibernation API（ctx.acceptWebSocket / webSocketMessage / webSocketClose）
// ——不是 `server.accept()`。区别很关键：`accept()` 建的连接只要开着就一直算
// active、一直计费；Hibernation 下 DO 在没消息时可以被冻结（不计费），消息
// 一来自动解冻——代价是解冻后内存清零，所以任何要跨消息记住的东西都不能放
// 在实例字段上，只能落 DO storage（SQL）或 ws.serializeAttachment()。
//
// 集成测试待 wrangler dev 手验：本文件依赖 Cloudflare 运行时全局
// （WebSocketPair、ctx.acceptWebSocket 等），本机没有真实 DO 环境跑不了它——
// 已把所有可以脱离运行时单测的逻辑抽进 envelope.js / auth.js / quota.js /
// room-store.js，那四个文件在 test/ 下有真跑过的单测；本文件（room-do.js）
// 用一个 mock-ctx 单测替身（test/room-do.test.js）绕开 WebSocketPair/
// Hibernation API，直接驱动 webSocketMessage/webSocketClose/fetch 的鉴权
// 分支，覆盖了消息路由/角色方向/配额降级这几块本来测不到的逻辑；真正测不了
// 的只剩 Hibernation 生命周期本身。
//
// ============================================================================
// T4 修复轮（opus 复核裁决）：上一版骨架自己猜了一层 `{ envelope, milestone,
// command_id }` 外层包装、且假设 milestone/command_id 是「relay 自己需要的
// 路由手柄」。按此复核结果订正——协议改成**单层信封**，不再有外层包装：
//
//   { v, room, epoch, kind, session, command_id, seq, ct, n, ts }
//
// - `kind` 本身就是路由手柄：新增 "live" 值（只转发、永不落库、seq 恒
//   null），取代旧版「kind=event + milestone 布尔位」的组合表达——不再需要
//   一个外层旗标来区分「这条 event 该不该盖 seq」，kind="event" 恒等于
//   里程碑、kind="live" 恒不落库。
// - `command_id` 从外层临时字段转正为信封顶层字段，kind=input|control 均必填，
//   kind=event|live|presence 禁止携带；两类指令自 v1.7.3 起共用明文帧
//   `input.ack {command_id, outcome}`（与 presence / control.notify_hint 同类，
//   relay 要靠它清空 pending_input 队列，从不解密 ct）。
//
// 这一版 room-do.js 已按订正协议重写；envelope.js 的 validateEnvelope /
// buildAAD 同步调整（详见该文件头注释）。
// ============================================================================

import {
  PROTOCOL_VERSION,
  ENVELOPE_KINDS,
  validateEnvelope,
  validatePairAcceptFrame,
} from "./envelope.js";
import {
  matchesOwnerCredential,
  parseBearerAuthorization,
  parseRemoteSubprotocol,
  sha256AsciiHex,
} from "./auth.js";
import { DEFAULT_MONTHLY_MILESTONE_LIMIT, currentPeriod, evaluateQuota, shouldDegrade } from "./quota.js";
import * as store from "./room-store.js";

// serializeAttachment 的字节预算：口径是 ≤16KB。
// 这里只做一个粗防线（用 JSON 字符串长度近似字节数，纯 ASCII 场景下等价；
// 附件里目前只有 epoch/role/lastSeq/connectedAt 几个数字/短字符串字段，
// 天然远小于预算——真正需要这道防线的是未来往附件里塞更多东西的人）。
const ATTACHMENT_BYTE_BUDGET = 16 * 1024;
const FRAME_BYTE_BUDGET = 64 * 1024;
const SYNC_ENTRY_LIMIT = 256;
const REGISTRY_SYNC_TIMEOUT_MS = 30_000;
const CLAIM_BODY_BYTE_BUDGET = 1024;
const TOMBSTONE_CLOSE_CODE = 1008;
const TOMBSTONE_CLOSE_REASON = "room_tombstoned";
const REAUTH_CLOSE_CODE = 1008;
const REAUTH_CLOSE_REASON = "token_reauthorization_failed";
// G8 R3（双路审 fix_required③）：消息限速踢连接专属 reason——不能复用上面
// 的 REAUTH_CLOSE_REASON，那个字符串会让手机端把「发太快被限速」误判成
// 「凭据坏了」去走重新配对流程；这里的真实原因只是节流，正常退避重连就该
// 恢复，不该触发重新配对。
const MESSAGE_RATE_LIMIT_CLOSE_CODE = 1008;
const MESSAGE_RATE_LIMIT_CLOSE_REASON = "message_rate_limited";
const RC_SUBPROTOCOL = "agentloom-rc-v1";
const UPGRADE_FINE_LIMIT = 60;
const UPGRADE_COARSE_LIMIT = 120;
const UPGRADE_FAILURE_WINDOW_MS = 60_000;
const PAIR_HELLO_LIMIT = 6;
const PAIR_HELLO_WINDOW_MS = 60_000;
const SUBJECT_SOCKET_LIMIT = 4;
// S1i2 §9.6 第 246 行：relay 侧等桌面 ok/fail 回执的窗口——桌面此时必已在线
// 且 registry_ready（否则 handleTokenRefresh 直接回 desktop_offline、不建
// 行），与 REGISTRY_SYNC_TIMEOUT_MS 同一口径：一段正常往返该在这窗口内走完，
// 过期就删行，手机走 resend 重绑 connection_id 恢复。
const REFRESH_REQUEST_TTL_MS = 30_000;
// §9.6/§9.8 配额：per-socket 6/min，同 request_id 重发不计配额——复用
// pair.hello 的 attachment 滑窗设施同款模式（takeRefreshRequestSlot）。
const REFRESH_REQUEST_LIMIT = 6;
const REFRESH_REQUEST_WINDOW_MS = 60_000;
// S1i2 返工 R4（§9.6/§9.8 v1.8.5）：resend 免主配额是规范字面（同 request_id
// 重放不计配额），但字面本身留了口子——relay 只按 request_id+subject 判定
// 重放、不核 ct/n（也不该核，零解析）,持合法凭据者可用同一个 id 无限触发
// 「一次桌面 forward + 一次 DB upsert」、绕过主桶持续消耗桌面解密。独立宽松
// 桶兜底：默认 30/min/socket——远高于任何正常崩溃恢复重放（手机重启复用同
// id）的真实频率，只挡「持续刷同一个 id」这一种滥用形态。
const REFRESH_RESEND_LIMIT = 30;
const REFRESH_RESEND_WINDOW_MS = 60_000;
// S1i2 返工 R2（同 §9.5 command_id 128 字节上限口径·envelope.js:135-138）：
// request_id 直接落 refresh_requests.request_id PRIMARY KEY 并回写进 forward
// 帧，帧预算 64KB 下不设上限等于放行「已认证设备 → 持久存储膨胀」的成本
// 不对称写入；同口径 128 字节，按 UTF-8 字节计。
const REQUEST_ID_MAX_BYTES = 128;
// SEC-3：未认领房（room_state.owner_credential_hash == null）到点自杀回收
// 的固定宽限窗——起点是 room_state.created_at（fresh 房=真实建房时刻，存量
// 迁移房=首次触碰时刻，见 room-store.js initRoomStateSentinel），窗口本身
// 固定不随后续 fetch()/alarm() 滑动。远大于正常「建房→配对→claim」耗时，
// 避免误杀仍在正常配对流程中的房间。
const UNCLAIMED_RECLAIM_MS = 20 * 60 * 1000;
// 单 socket 攒够这么多协议违规就踢掉它；聚合计数也按同一批量落库一次
// （每帧一次 SELECT+UPSERT 等于把「乱发帧」变成「白嫖写」，见 §6b 防打爆）。
const PROTOCOL_VIOLATION_LIMIT = 8;
// G8（C1 设计 v0.5 §8·消息期限速·codex 设计审 Critical-2，双路（codex+opus）
// 二审 fix_required 后按 Lead 拍板的桶拓扑重构）：威胁模型是被盗的已配对
// 手机（合法凭据）——① 桌面在线时无限灌 input.send/control 直达 agent 执行
// 路径；② 桌面离线时无限撑 pending_input；③ 反复 control.stop 骚扰。
//
// R1：per-subject 桶不再存 attachment——威胁模型的行为体（被盗已配对手机）
// 完全掌控自己何时断线重连，存 attachment 的桶断一次重连就清零，形同虚设。
// 改成 message_rate_limits SQL 表（room-store.js takeMessageRateSlot）：
// 同 subject 的多个并发 socket 共享同一份 (subject, channel) 配额，跨
// socket/跨重连/跨休眠不丢——这才是设计稿 §8 字面的「per-subject」，不是
// 先前误解的「per-subject 有效上界 = 4×并发数」。见
// takeSubjectChannelRateSlot。
const INPUT_RATE_LIMIT = 30;
const INPUT_RATE_WINDOW_MS = 60_000;
const CONTROL_RATE_LIMIT = 30;
const CONTROL_RATE_WINDOW_MS = 60_000;
// R2：per-IP 粗桶挪到中央入站点（webSocketMessage 里 scope 矩阵通过之后、
// 明文/信封分流之前），对这个 IP 上所有 role=remote 的入站帧计费——不再
// 局限于 input/control 两种帧型，堵掉「validateEnvelope 才会验出无效的
// 信封垃圾帧从不经过 handleInput/handleControl、白嫖一条免费探测回环」这个
// 口子。阈值从「单 subject 用满 4 个 socket 的 input+control 合法上界」
// （4×30+4×30=240）改成它的两倍 480——粗桶必须留出高于任何单 subject 合法
// 峰值的余量，否则一个老实的多设备用户自己就会先踩线（opus 数值论证）；
// 超限只回错误帧、绝不踢连接（R2 opus B1 定罪：旧版超限即踢的做法会让
// 共享同一个 ip_bucket_key 的无辜邻居设备被同房作恶者连累下线——尤其
// wrangler dev 本地环境下 CF-Connecting-IP 缺失时，deriveIpBucketKey 对
// 「所有」连接塌缩成同一个桶键，480 阈值 + 只拒不踢的组合下这种塌缩仍可
// 容忍：顶多本地测试互相顶到一起报错，不会有人被断线）。结构仍是 Map+
// bucketAtLimit/recordBucketHit（同 upgrade 粗桶一族·isolate 生命周期，
// 不持久，DO 休眠重建即清零）。
const IP_MESSAGE_RATE_LIMIT = 480;
const IP_MESSAGE_RATE_WINDOW_MS = 60_000;
// R2 附带风险（codex 一审）+ R1 三审 fix_required（codex xhigh 差量审）：
// 中央挂点覆盖面比旧版（只挂 input/control）大得多，一个长寿命 isolate
// 理论上会见到远更多不同的 ip_bucket_key。这是真硬上限，不是"超过才顺手
// 扫一下"的软提示——Map 里不同 key 的数量永远不会超过这个数：插入一把
// 从没见过的新 key 时若已经顶到这个数，先试着清一遍过期窗口腾位置，清完
// 还是顶着就直接拒绝这一帧（fail-closed），绝不为了腾位置去牺牲正在计数
// 的活跃桶。见 takeIpMessageSlot。
const IP_MESSAGE_BUCKET_MAX_ENTRIES = 4096;
// pending_input 离线暂存上限（威胁模型②）：行数与总字节各自独立闸，任一
// 超限即拒绝入队，回 queue_full——不影响已暂存的行，只挡新的膨胀。
// R4：容量判断前先清过期行（死行不占死容量）、幂等先于容量（满队列时同
// command_id 重试不该收假 queue_full）——见 handleInput 调用点注释。
const PENDING_INPUT_ROW_LIMIT = 256;
const PENDING_INPUT_BYTE_LIMIT = 4 * 1024 * 1024; // 4MB（envelope 长度和，UTF-8 字节）
const INBOUND_SCOPE_MATRIX = Object.freeze({
  pairing: new Set(["pair.hello", "pair.done"]),
  remote: new Set(["input", "control", "presence", "token.refresh"]),
  refresh: new Set(["token.refresh"]),
  desktop: new Set([
    "event",
    "live",
    "control.notify_hint",
    "input.ack",
    "pair.accept",
    "pair.ready",
    "token.put",
    "token.delete",
    "token.sync",
    "token.reset",
    "token.refresh.ok",
    "token.refresh.fail",
  ]),
});

function cfSqlAdapter(storage) {
  return {
    exec(query, ...params) {
      return [...storage.sql.exec(query, ...params)];
    },
    transactionSync(callback) {
      return storage.transactionSync(callback);
    },
  };
}

export class RoomDO {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
    this.sql = cfSqlAdapter(ctx.storage);
    this.upgradeFineBuckets = new Map();
    this.upgradeCoarseBuckets = new Map();
    // G8：per-IP 消息期粗桶——isolate 生命周期内存 Map，同 upgrade 粗桶一族，
    // 不落 SQL、不跨休眠（休眠重建即清零，够挡持续洪泛）。
    this.ipMessageBuckets = new Map();
    // 违规计数分两层：per-socket 在内存里（踢连接用，休眠清零即重新计），
    // 房间聚合攒够 PROTOCOL_VIOLATION_LIMIT 或 close/alarm 时才落一次库。
    this.socketProtocolViolations = new WeakMap();
    this.pendingProtocolViolations = 0;
    this.ipBucketSalt = null;

    // Sentinel bootstrap 顺序是生命周期契约的一部分：无条件调一次，不再拿
    // `!hasTable("room_state")` 挡——initRoomStateSentinel 内部全幂等
    // （CREATE TABLE IF NOT EXISTS + 守卫式 ALTER 补 ip_bucket_salt 列 +
    // INSERT ... WHERE NOT EXISTS），fresh 房三步全是空操作到真正建表，存量房
    // （room_state 已存在但预 SEC-1、没有 ip_bucket_salt 列）三步分别是
    // 空操作/真正补列/空操作。SEC-1 复现修复：guard 版本下存量房的守卫式
    // ALTER 永远够不到（挡在 !hasTable 外面），列补不上，deriveIpBucketKey
    // 每次 upgrade 都会撞 `no such column: ip_bucket_salt` 崩——去掉这层
    // guard 后存量房也能在构造时把列补齐。（存量房这次迁移会让 ip_bucket_key
    // 的盐旋转一次：迁移前 room_meta 里的旧盐不搬，直接在 room_state 里现生成
    // 一份新的——salt 消费方全部只是「同房间同 IP 落同一个桶」的相对稳定性
    // 而非跨迁移前后必须逐比特相等的持久正确性，旋转一次无安全/正确性损害）。
    // 墓碑房绝不能再触发业务 schema/backfill——业务 schema（11 张表 + IP 盐
    // 落库时机）不在这里无条件建：构造器只建/补 room_state 哨兵，业务 schema
    // 延到 fetch() 鉴权成功后才建（见下方 ensureBusinessSchema 插桩点）；
    // this.ipBucketSalt 留 null，deriveIpBucketKey 已有懒加载分支。
    store.initRoomStateSentinel(this.sql);
  }

  async fetch(request) {
    const url = new URL(request.url);
    const roomIdMatch = url.pathname.match(/^\/room\/([0-9a-f]{32})/);
    const roomId = roomIdMatch ? roomIdMatch[1] : null;
    const claimPath = roomId ? `/room/${roomId}/claim` : null;
    const roomPath = roomId ? `/room/${roomId}` : null;

    if (!this.assertRoomLive()) {
      return new Response("room gone", { status: 410 });
    }

    if (request.method === "POST" && url.pathname === claimPath) {
      return this.handleClaim(request);
    }

    if (request.method === "DELETE" && url.pathname === roomPath) {
      return this.handleDelete(request);
    }

    if (request.headers.get("Upgrade") !== "websocket") {
      // SEC-3 修复轮（独立 skeptic 复现的真实缺口）：裸 GET / 错路径 POST 等
      // 非 upgrade 请求撞中这里，跟 rejectUpgradeAuthentication/handleClaim
      // 一样，从不触达 fetch() 握手成功后的既有 scheduleNextTokenAlarm() 调用
      // （:339 一线）——不补武装的话，纯用这条比 WS upgrade 尝试更便宜的路径
      // 探测未认领房，能永远绕过 SEC-3 防刷房回收。owner 非 null 时不进——
      // 同一个误杀防线不变量。
      if (store.getRoomState(this.sql).owner_credential_hash == null) {
        await this.scheduleNextTokenAlarm();
      }
      return new Response("expected websocket upgrade", { status: 426 });
    }

    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const ipBucketKey = await this.deriveIpBucketKey(ip);
    const bearer = parseBearerAuthorization(request);
    let role = "remote";
    let admission = null;
    let echoRemoteProtocol = false;
    if (bearer.provided) {
      const ownerHash = store.getRoomState(this.sql).owner_credential_hash;
      if (!(await matchesOwnerCredential(bearer.credential, ownerHash))) {
        const prefix = (await sha256AsciiHex(bearer.credential || "missing")).slice(0, 8);
        return this.rejectUpgradeAuthentication(ipBucketKey, prefix);
      }
      if (!this.assertRoomLive()) {
        return new Response("room gone", { status: 410 });
      }
      role = "desktop";
      admission = { scope: "desktop" };
    } else {
      // S1ja §9.7 后门退役：__admin/register-token + ADMIN_TOKEN 与 legacy
      // `?token=`/valid_tokens 准入路径已删——正式远端连接只认 §9.1 的子协议
      // token（下面这一枝），不再有任何回落到 room_meta.valid_tokens 的旁路。
      const subprotocol = parseRemoteSubprotocol(request);
      if (!subprotocol.provided || !subprotocol.ok) {
        const prefix = (await sha256AsciiHex(
          request.headers.get("Sec-WebSocket-Protocol") || "missing"
        )).slice(0, 8);
        return this.rejectUpgradeAuthentication(ipBucketKey, prefix);
      }
      const tokenHash = await sha256AsciiHex(subprotocol.token);
      admission = store.resolveTokenAdmission(this.sql, tokenHash, Date.now());
      if (!admission) {
        return this.rejectUpgradeAuthentication(ipBucketKey, tokenHash.slice(0, 8));
      }
      echoRemoteProtocol = true;
    }

    // SEC-1：业务 schema（11 张表）延到鉴权成功后才建——两条鉴权枝（bearer
    // desktop / 子协议 remote token）在这里汇流，鉴权失败的 reject 分支（上面
    // 的 rejectUpgradeAuthentication 提前 return）永远够不到这一行；socket
    // accept 在这一行之后，业务 handler 用表前 schema 已经在。刷房打随机
    // /room/<hex> 不再触发 11 张业务表 + IP 盐持久存储的账单。
    store.ensureBusinessSchema(this.sql);

    // M2：鉴权通过之后才落 room_meta 行。之前这行在鉴权前面跑，意味着任何
    // 打中 /room/<随机32位hex> 的请求——不管带没带对令牌——都会先触发一次
    // DO 实例化 + 一行 SQL 写入，把「枚举房间 id」的攻击面变成了「白嫖一次
    // 写」。鉴权失败的请求现在到不了这一行。
    if (roomId) store.ensureRoomId(this.sql, roomId);

    const requestedLastSeq = Number(url.searchParams.get("last_seq") || 0);

    // eslint-disable-next-line no-undef -- Cloudflare Workers 运行时全局
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);

    // 桌面每次连上来，epoch +1、此后拒绝旧 epoch 的写入（防双写）。
    // 远端连接只是「读」当前 epoch，不推进它。
    const epoch = role === "desktop" ? store.bumpEpoch(this.sql) : store.getCurrentEpoch(this.sql);
    if (role === "desktop") {
      this.broadcastReplacedDesktopOffline(epoch);
      // P0-d1（订正遗留的可用性缺口）：
      // 桌面重连后 epoch 抬升，relay 之前从不通知在线远端——旧 epoch 只能等
      // 下一次写入撞 stale_epoch 才发现代已经变了。这里在 bump 落库后立即广播
      // 明文帧，走 broadcastToRemotes 同族出站闸（canDeliverOutbound：只投给
      // 当前权威、kind="current" 的活 remote 连接，同 presence 等既有明文
      // 广播帧一致），不新开投递路径、不绕闸。
      this.broadcastToRemotes({ t: "epoch.changed", epoch, ts: Date.now() });
    }

    const attachment = {
      epoch,
      role,
      scope: admission.scope,
      subject: admission.subject ?? null,
      kind: admission.kind ?? null,
      generation: admission.generation ?? null,
      alias_generation: admission.alias_generation ?? null,
      access_expires: admission.access_expires ?? null,
      valid_until: admission.valid_until ?? null,
      connection_id: globalThis.crypto.randomUUID(),
      lastSeq: admission.scope === "remote" ? requestedLastSeq : store.headSeq(this.sql),
      connectedAt: Date.now(),
      ip_bucket_key: ipBucketKey,
      ...(role === "desktop" ? {
        registry_ready: false,
        registry_sync_deadline: Date.now() + REGISTRY_SYNC_TIMEOUT_MS,
      } : {}),
    };
    this.assertAttachmentBudget(attachment);
    server.serializeAttachment(attachment);
    if (attachment.subject) this.enforceSubjectSocketLimit(attachment.subject);
    this.ctx.acceptWebSocket(server, [role]); // Hibernation API —— 不是 server.accept()
    if (attachment.subject || role === "desktop") await this.scheduleNextTokenAlarm();

    if (admission.scope === "remote") {
      this.replayTo(server, requestedLastSeq);
    }
    if (role !== "desktop") this.broadcastPresence(role, "online", server);

    const headers = echoRemoteProtocol ? { "Sec-WebSocket-Protocol": RC_SUBPROTOCOL } : undefined;
    return new Response(null, { status: 101, webSocket: client, headers });
  }

  async handleClaim(request) {
    // SEC-3：claim POST 是「对未认领房的实例化」的另一个 brief 原话例子——
    // 不论请求体后续解析成不成功、claim 最终成不成功，这条路径也从不会走到
    // fetch() 握手成功后的既有 scheduleNextTokenAlarm() 调用（:333 一线）。
    // 放在最前面，覆盖这个入口的所有出口（含下面几处 400 早退）。owner 非
    // null（已 claim/冲突）时不进——同一个误杀防线不变量。
    if (store.getRoomState(this.sql).owner_credential_hash == null) {
      await this.scheduleNextTokenAlarm();
    }
    const contentLength = Number(request.headers.get("Content-Length"));
    if (Number.isFinite(contentLength) && contentLength > CLAIM_BODY_BYTE_BUDGET) {
      return new Response("payload too large", { status: 413 });
    }

    let bytes;
    try {
      bytes = new Uint8Array(await request.arrayBuffer());
    } catch {
      return new Response("bad request", { status: 400 });
    }
    if (bytes.byteLength > CLAIM_BODY_BYTE_BUDGET) {
      return new Response("payload too large", { status: 413 });
    }

    let body;
    try {
      body = JSON.parse(new TextDecoder().decode(bytes));
    } catch {
      return new Response("bad request", { status: 400 });
    }
    if (body?.v !== 1 || !/^[0-9a-f]{64}$/.test(body?.credential_hash || "")) {
      return new Response("bad request", { status: 400 });
    }

    const result = store.claimRoom(this.sql, body.credential_hash, Date.now());
    if (result === "rate_limited") return new Response("rate limited", { status: 429 });
    if (result === "tombstoned") return new Response("room gone", { status: 410 });
    if (result === "conflict") return new Response("owner conflict", { status: 409 });
    return new Response("ok", { status: 200 });
  }

  async handleDelete(request) {
    const bearer = parseBearerAuthorization(request);
    const ownerHash = store.getRoomState(this.sql).owner_credential_hash;
    if (!bearer.provided || !(await matchesOwnerCredential(bearer.credential, ownerHash))) {
      // SEC-3 修复轮（独立 skeptic 复现的真实缺口）：DELETE 打未认领房
      // （owner==null）恒 401，且这条分支从不触达 fetch() 握手成功后的既有
      // scheduleNextTokenAlarm() 调用（:339 一线）——不补武装的话，纯用
      // DELETE 探测未认领房能永远绕过 SEC-3 防刷房回收。owner 非 null（房
      // 已认领、只是凭据错）时不进——同一个误杀防线不变量。
      if (ownerHash == null) {
        await this.scheduleNextTokenAlarm();
      }
      return new Response("unauthorized", { status: 401 });
    }

    const tombstoned = store.tombstoneRoom(this.sql, Date.now());
    if (!tombstoned) {
      return new Response("room gone", { status: 410 });
    }

    // 事务提交后才处理 SQL 外的副作用，避免回滚时房间已被提前踢空。
    this.closeAllSockets();
    if (typeof this.ctx.storage.deleteAlarm === "function") {
      await this.ctx.storage.deleteAlarm();
    }
    return new Response("ok", { status: 200 });
  }

  async webSocketMessage(ws, message) {
    if (!this.assertRoomLive()) {
      this.closeSocketForTombstone(ws);
      return;
    }

    let text;
    try {
      if (typeof message === "string") {
        text = message;
        if (new TextEncoder().encode(text).byteLength > FRAME_BYTE_BUDGET) {
          this.rejectOversizedFrame(ws);
          return;
        }
      } else {
        const bytes = message instanceof ArrayBuffer
          ? new Uint8Array(message)
          : ArrayBuffer.isView(message)
            ? new Uint8Array(message.buffer, message.byteOffset, message.byteLength)
            : null;
        if (!bytes) throw new TypeError("unsupported websocket message");
        if (bytes.byteLength > FRAME_BYTE_BUDGET) {
          this.rejectOversizedFrame(ws);
          return;
        }
        text = new TextDecoder().decode(bytes);
      }
    } catch {
      ws.send(JSON.stringify({ t: "error", reason: "bad_json" }));
      return;
    }

    const attachment = safeAttachment(ws);
    if (!this.authorizeInboundSocket(ws, attachment)) return;

    let payload;
    try {
      payload = JSON.parse(text);
    } catch {
      ws.send(JSON.stringify({ t: "error", reason: "bad_json" }));
      return;
    }

    if (!payload || typeof payload !== "object") {
      ws.send(JSON.stringify({ t: "error", reason: "bad_payload" }));
      return;
    }

    const role = attachment.role;
    const frameType = typeof payload.t === "string" ? payload.t : payload.kind;
    const allowedTypes = INBOUND_SCOPE_MATRIX[attachment.scope];
    if (typeof frameType !== "string" || !allowedTypes?.has(frameType)) {
      const exceeded = this.recordProtocolViolation(ws);
      const error = {
        t: "error",
        reason: "role_forbidden",
        role: role ?? null,
      };
      if (typeof payload.t === "string") error.frame = payload.t;
      else if (typeof payload.kind === "string") error.kind = payload.kind;
      ws.send(JSON.stringify(error));
      // 矩阵外帧本身是「拿着合法凭据乱扫」的形态：回错误但连接留着，等它攒够
      // PROTOCOL_VIOLATION_LIMIT 次再踢，免得一次手滑就断线。
      if (exceeded) this.closeSocketForReauthorization(ws);
      return;
    }

    // G8 R2（双路审 fix_required②）：per-IP 消息期粗桶——中央入站点，scope
    // 矩阵刚通过（frameType 确认是这个 scope 允许的帧型）、明文/信封分流之前，
    // 对这个 IP 上所有 role=remote 的入站帧计费，不管这条帧接下来是走
    // handlePlainFrame 还是 validateEnvelope、也不管 validateEnvelope 最终
    // 判它合法还是垃圾——旧版把闸设在 handleInput/handleControl 内部，只在
    // envelope 校验通过、真正进了这两个 handler 之后才计费，一条 kind=input
    // 但 ct/n 是垃圾的帧会在 validateEnvelope 那步就被挡掉、根本走不到那
    // 两个闸，等于一条不计费的免费探测回环。desktop 角色的帧不挂这个桶——
    // 它们走完全不同的 scope="desktop" 分支，人是自己人，不是威胁模型里的
    // 「被盗手机」。
    if (role === "remote" && !this.takeIpMessageSlot(ws, frameType, payload.command_id)) return;

    if (typeof payload.t === "string" && attachment.role === "desktop" &&
        attachment.scope === "desktop" &&
        Number(attachment.epoch) !== store.getCurrentEpoch(this.sql)) {
      const currentEpoch = store.getCurrentEpoch(this.sql);
      try {
        ws.send(JSON.stringify({ t: "error", reason: "stale_epoch", currentEpoch }));
      } finally {
        this.closeSocketForReauthorization(ws);
      }
      return;
    }

    if (attachment.role === "desktop" && attachment.scope === "desktop" &&
        attachment.registry_ready !== true && frameType !== "token.sync") {
      if (["token.put", "token.delete"].includes(frameType)) {
        this.rejectTokenMutation(ws, payload, "sync_required");
      } else {
        ws.send(JSON.stringify({ t: "error", reason: "sync_required", frame: frameType }));
      }
      return;
    }

    // 单层信封（T4 修复轮）：WS 消息要么是一个明文控制帧（顶层 `t` 字段，
    // presence / control.notify_hint / input.ack），要么本身就是 §1 订正版
    // 定义的信封——不再有外层 `{envelope: ...}` 包装，payload 本身直接拿去
    // 校验/转发。
    if (typeof payload.t === "string") {
      this.handlePlainFrame(ws, payload, role);
      return;
    }

    const validation = validateEnvelope(payload);
    if (!validation.ok) {
      ws.send(JSON.stringify({ t: "error", reason: "invalid_envelope", errors: validation.errors }));
      return;
    }
    const envelope = validation.envelope;

    // H1：role 强制方向。远端不产里程碑——否则任何持有 K_room 的远端设备
    // 都能伪造一条「agent 说的话」广播给房间里其它人，还会被落库、被将来的
    // 重连当成真实历史回放。桌面不发 input——input 通道的语义是「远端替
    // 用户敲的东西」，桌面自己不需要通过这条通道给自己发指令。违反方向的
    // 一律拒绝 + 回错误帧，不静默丢弃（同「防打爆」一贯的做法）。
    if (envelope.kind === "event" && role !== "desktop") {
      ws.send(JSON.stringify({ t: "error", reason: "role_forbidden", kind: envelope.kind, role }));
      return;
    }
    if (envelope.kind === "input" && role !== "remote") {
      ws.send(JSON.stringify({ t: "error", reason: "role_forbidden", kind: envelope.kind, role }));
      return;
    }
    // 远端发 live 等于冒充桌面广播 agent 流式输出，是瞬时视觉污染攻击。
    if (envelope.kind === "live" && role !== "desktop") {
      ws.send(JSON.stringify({ t: "error", reason: "role_forbidden", kind: envelope.kind, role }));
      return;
    }

    switch (envelope.kind) {
      case "event":
        this.handleEvent(ws, envelope);
        return;
      case "live":
        this.handleLive(ws, envelope);
        return;
      case "input":
        this.handleInput(ws, envelope, envelope.command_id);
        return;
      case "control":
        this.handleControl(ws, envelope);
        return;
      case "presence":
        this.broadcastRaw(envelope, ws);
        return;
      default:
        // validateEnvelope 已经把 kind 限定在 ENVELOPE_KINDS 内，这里到不了；
        // 留一条防线防未来 ENVELOPE_KINDS 加了新值却忘了在这里接。
        ws.send(JSON.stringify({ t: "error", reason: "unhandled_kind", kinds: ENVELOPE_KINDS }));
    }
  }

  async webSocketClose(ws) {
    if (!this.assertRoomLive()) {
      this.closeSocketForTombstone(ws);
      return;
    }
    this.flushProtocolViolations();
    const att = safeAttachment(ws);
    if (att.role !== "desktop" || (att.registry_ready === true &&
        Number(att.epoch) === store.getCurrentEpoch(this.sql))) {
      this.broadcastPresence(att.role || "remote", "offline", ws);
    }
  }

  async webSocketError() {
    // Hibernation API 要求实现这个回调；骨架不做特殊处理——重连是客户端的责任。
  }

  async alarm() {
    if (!this.assertRoomLive()) {
      this.closeAllSockets();
      return;
    }
    // SEC-3：未认领空房自杀回收——放在 ensureBusinessSchema 与下面三类逻辑
    // 之前（回收枝只摸 room_state，不需要业务 schema；F2-A 起改走
    // storage.deleteAll 整库清空，不管当时存不存在的其它表，不需要先在这里把
    // 它们建出来）。
    // ★误杀防线（核心不变量）：硬门 = owner_credential_hash == null，不是
    // 「无连接」。已 claim 但暂时无连接的正常空房 owner 非 null，永远不会
    // 进这一枝。getWebSockets().length===0 只是防御性叠加——owner==null 的
    // 房不可能有活的已认证 socket（desktop 走 bearer 认证，
    // matchesOwnerCredential 对 null ownerHash 恒 false；remote 走
    // token_subjects/token_aliases，那两张表只由 desktop 的 token.put 写，
    // desktop 连不上就永远不会有行，resolveTokenAdmission 永远打不中）。
    // claim/reclaim 竞态：DO 单线程、都是同步事务不交错；这里到点**实时
    // 重查** owner（不信调度快照）——claim 先提交则这里看到 owner 非 null、
    // 跳过；reclaim 先则后续 claim 见 state.tombstoned_at != null，
    // claimRoom 已有分支回 "tombstoned"，handleClaim 映射成 410。
    const unclaimedState = store.getRoomState(this.sql);
    if (unclaimedState.owner_credential_hash == null && this.ctx.getWebSockets().length === 0) {
      const createdAt = unclaimedState.created_at == null ? null : Number(unclaimedState.created_at);
      if (createdAt != null && Date.now() >= createdAt + UNCLAIMED_RECLAIM_MS) {
        // F2-A（用户拍·整盘审 F2）：未认领房到点回收改彻底清房，不再走墓碑
        // 保留。旧行为（tombstoneRoom）只 DELETE 业务表行、留 room_state 墓碑
        // 行——DO 只要有任何存储残留就永久驻留（计费/配额账单不清零），刷房
        // 产生的死房因此永远占着。deleteAll() 对 SQLite-backed DO 的语义（已
        // 查证 Cloudflare 官方文档：developers.cloudflare.com/durable-objects/
        // api/storage-api/）——清空整个私有 SQLite 数据库，含 sql.exec 建的
        // 所有表和 KV 数据，操作原子（all-or-nothing，不存在部分删除的中间态）；
        // 现行 wrangler.toml compatibility_date=2026-08-01（>= 2026-02-24 门槛）
        // 下 deleteAll() 本身也会带走 alarm，这里仍显式先调 deleteAlarm 做防御
        // 性双保险（不依赖 compat date、未来降级也不会漏删）。deleteAll 之后
        // SQL 表已不存在，不能再碰 this.sql——直接 return。
        // 墓碑语义损失已论证无害：未认领房 id 是 128bit 随机、从无合法拥有者；
        // deleteAll 后同 id 再被打入一个全新 RoomDO 实例，构造器
        // initRoomStateSentinel 无条件重建哨兵表——等价于又一个全新未认领房，
        // 到点再收，收敛。已认领房（owner 非 null）与显式 DELETE 解散场景不
        // 经过这一枝，墓碑 410 语义原样保留（见 handleDelete: tombstoneRoom）。
        await this.ctx.storage.deleteAlarm?.();
        await this.ctx.storage.deleteAll();
        return;
      }
    }
    // F1（T4 修复轮·整盘审实锤）：上面的回收枝只处理「owner==null 且到点」这
    // 一种情况；owner 非 null（已 claim）或还没到点的未认领房都会落到这里。
    // 未鉴权 POST /claim 能让任意调用者把 owner 落库、却从不经过 fetch() 鉴权
    // 成功才建业务 schema 的那条路径——若这里仍无条件 ensureBusinessSchema，
    // 到点的 alarm 就会替一次从未鉴权成功的请求兜底建出 11 张业务表 + 13 索引，
    // 绕开 SEC-1「未鉴权请求零业务表」的核心不变量。没建过业务 schema 的房，
    // 说明它从未有过一次成功鉴权的 WS 会话——后面的 flush/deleteExpired
    // 过期 refresh 行/socket 遍历/scheduleNextTokenAlarm 本来就无事可做
    // （refresh_requests/pending_input 等表压根不存在，getWebSockets() 恒为
    // 空，scheduleNextTokenAlarm 的 min 候选在这种状态下也只会算出 null），
    // 早退在这里最干净。已认领且业务 schema 已建好的正常房（hasTable 恒
    // true）完全不受影响，token alarm 路径照旧往下走。
    if (!store.hasTable(this.sql, "room_meta")) return;
    // SEC-1 防御性兜底：正常路径业务 schema 已在 fetch() 鉴权成功时建好，这里
    // 只防未来排序意外（比如某次改动让 alarm 抢在任何鉴权请求之前先被调度）。
    // ensureBusinessSchema 幂等，重复调用安全。
    store.ensureBusinessSchema(this.sql);
    this.flushProtocolViolations();
    // R1（§9.6 第 249 行）：过期 refresh_requests 行真删，不只是查询时过滤——
    // 见 room-store.js deleteExpiredRefreshRequests 头注释。
    store.deleteExpiredRefreshRequests(this.sql, Date.now());
    for (const ws of this.ctx.getWebSockets()) {
      const attachment = safeAttachment(ws);
      if (attachment.role === "desktop" && attachment.scope === "desktop" &&
          attachment.registry_ready !== true &&
          Number.isSafeInteger(Number(attachment.registry_sync_deadline)) &&
          Number(attachment.registry_sync_deadline) <= Date.now()) {
        this.closeDesktopForSyncTimeout(ws);
        continue;
      }
      if (attachment.subject && !this.isOfficialAttachmentLive(attachment, Date.now())) {
        this.closeSocketForReauthorization(ws);
      }
    }
    await this.scheduleNextTokenAlarm();
  }

  // ---- kind=event：里程碑，恒落库盖 seq。H3：配额超限也不丢（
  // 见 quota.js 文件头的理由）——handleEvent 因此不查配额，只查 stale_epoch。 ----
  handleEvent(ws, envelope) {
    const currentEpoch = store.getCurrentEpoch(this.sql);
    if (envelope.epoch !== currentEpoch) {
      ws.send(JSON.stringify({ t: "error", reason: "stale_epoch", currentEpoch }));
      return;
    }

    const result = store.insertMilestone(this.sql, {
      epoch: envelope.epoch,
      session: envelope.session,
      kind: envelope.kind,
      ct: envelope.ct,
      n: envelope.n,
      ts: envelope.ts,
      client_msg_id: envelope.client_msg_id,
    });
    if (!result.ok) {
      ws.send(JSON.stringify({ t: "error", reason: result.reason, currentEpoch: result.currentEpoch }));
      return;
    }

    const stamped = { ...envelope, seq: result.seq };

    if (result.dedup) {
      // 幂等命中：不落新行、不重复计数配额、不广播给全房间——
      // 只回发送方一份既有 seq 的确认帧，形态与非去重路径下发送方收到的
      // stamped 自确认一致。
      ws.send(JSON.stringify(stamped));
      return;
    }

    store.incrementQuotaCount(this.sql, currentPeriod(Date.now()), 1);
    this.broadcastRaw(stamped, null); // 含发送方自己也收一份 seq 确认
  }

  // ---- kind=live：只转发、不落库、seq 恒 null；H3：配额超限时
  // 唯一允许被 shed 的流量——断的是这条通道，不是里程碑。 ----
  handleLive(ws, envelope) {
    const currentEpoch = store.getCurrentEpoch(this.sql);
    if (envelope.epoch !== currentEpoch) {
      ws.send(JSON.stringify({ t: "error", reason: "stale_epoch", currentEpoch }));
      return;
    }

    const quota = this.currentQuotaState();
    if (shouldDegrade("live", quota)) {
      // 同时广播给全房间（含远端），不是只回发送方——远端要能渲染出「本月
      // 额度已用完」，不能被静默丢包看着像网络抽风。
      this.broadcastRaw({ t: "quota.exceeded", channel: "live" }, null);
      return;
    }

    this.broadcastRaw(envelope, ws);
  }

  // ---- kind=input：FIFO·在线直转·离线暂存 30min TTL ----
  // G8：限速闸在最前——不管信封本身是否 stale_epoch/缺 command_id，都先占
  // 一个桶名额，防止用无效帧绕过限速白嫖判断成本（同 rejectUpgradeAuthentication
  // 的既有姿势：先判限速再判鉴权内容）。per-IP 粗桶已挪到中央入站点
  // （webSocketMessage，见那里的注释），这里只剩 per-subject 桶。
  handleInput(ws, envelope, commandId) {
    if (!this.takeSubjectChannelRateSlot(ws, envelope, {
      channel: "input", limit: INPUT_RATE_LIMIT, windowMs: INPUT_RATE_WINDOW_MS,
      reason: "input_rate_limited",
    })) return;

    const currentEpoch = store.getCurrentEpoch(this.sql);
    if (envelope.epoch !== currentEpoch) {
      ws.send(JSON.stringify({ t: "error", reason: "stale_epoch", currentEpoch }));
      return;
    }

    if (!commandId) {
      // G8 R5（双路审）：理论死代码——validateEnvelope 已保证 kind=input 的
      // command_id 非空非 undefined（envelope.js command_id_required_for_kind），
      // 这条分支到不了这里。留着当纵深防御，不删（同文件别处「理论不存在
      // 仍 fail-closed」的既有写法一致，例如 isPendingInputAuthorized 对
      // generation 为 NULL 的显式判断）。
      ws.send(JSON.stringify({ t: "error", reason: "missing_command_id" }));
      return;
    }

    const desktop = this.onlineDesktopForEpoch(currentEpoch);
    if (desktop) {
      desktop.send(JSON.stringify(envelope)); // envelope 自带 command_id（顶层唯一真相）
      return;
    }

    // G8 R4（双路审 fix_required④）：容量判断前先清过期行——TTL 到期的死行
    // 不该继续占着行数/字节容量，不清的话，房间可能因为一堆早该过期的旧行
    // 占满 256 行/4MB，把新的、真正需要暂存的 input 挤成假 queue_full。
    this.purgeExpiredPendingInput(Date.now());

    // G8 R4：幂等先于容量——同一个 command_id 重试（比如手机没收到上一次的
    // 确认、超时重发）本就不会让表再多一行（enqueueInput 是 ON CONFLICT
    // DO NOTHING），不该被容量闸误伤：不判断的话，队列刚好满员时的一次
    // 无害重试会被 rowCount>=LIMIT 挡下、回一个名不副实的 queue_full。
    if (store.hasPendingInputCommandId(this.sql, commandId)) return;

    // G8 威胁模型②：桌面离线时无限撑 pending_input——入队前核该房现存行数/
    // 总字节，任一超限就不入队，回 queue_full；不影响已暂存的行。
    const envelopeJson = JSON.stringify(envelope);
    const envelopeBytes = new TextEncoder().encode(envelopeJson).length;
    const pendingStats = store.pendingInputStats(this.sql);
    if (pendingStats.rowCount >= PENDING_INPUT_ROW_LIMIT ||
        pendingStats.totalBytes + envelopeBytes > PENDING_INPUT_BYTE_LIMIT) {
      // G8 R5：带 command_id——手机端要能把这条拒绝跟自己发出的哪条 input
      // 对上号，不然收到一条不知道是谁被拒的 queue_full 没法做精确重试/提示。
      ws.send(JSON.stringify({ t: "error", reason: "queue_full", frame: "input", command_id: commandId }));
      return;
    }

    store.enqueueInput(this.sql, {
      commandId,
      session: envelope.session,
      envelopeJson,
      now: Date.now(),
      subject: safeAttachment(ws).subject ?? null,
      generation: safeAttachment(ws).generation ?? null,
    });
  }

  // ---- kind=control：即刻投递、不暂存；桌面离线则丢弃并告知发送方 ----
  handleControl(ws, envelope) {
    if (!this.takeSubjectChannelRateSlot(ws, envelope, {
      channel: "control", limit: CONTROL_RATE_LIMIT, windowMs: CONTROL_RATE_WINDOW_MS,
      reason: "control_rate_limited",
    })) return;

    const currentEpoch = store.getCurrentEpoch(this.sql);
    if (envelope.epoch !== currentEpoch) {
      ws.send(JSON.stringify({ t: "error", reason: "stale_epoch", currentEpoch }));
      return;
    }
    const desktop = this.onlineDesktopForEpoch(currentEpoch);
    if (!desktop) {
      ws.send(JSON.stringify({ t: "error", reason: "desktop_offline" }));
      return;
    }
    desktop.send(JSON.stringify(envelope));
  }

  // ---- 明文控制帧 ----
  handlePlainFrame(ws, payload, role) {
    switch (payload.t) {
      case "presence":
        this.broadcastRaw(payload, ws);
        return;
      case "control.notify_hint":
        // 桌面 → relay，只带 {category}；转发给房间内在线远端。
        // 触发 Web Push 是 M5 的事，本单不做。
        // H1：仅接受来自桌面连接——这条通道的语义是「桌面通知远端」，远端
        // 假冒这一帧等于给房间广播一条冒充桌面发出的假提醒。
        if (role !== "desktop") {
          ws.send(JSON.stringify({ t: "error", reason: "role_forbidden", frame: "control.notify_hint", role }));
          return;
        }
        this.broadcastToRemotes(payload);
        return;
      case "input.ack":
        // H1：仅接受来自桌面连接——ack 的语义是「桌面确认收到了这条
        // input」，远端假冒会让 relay 把还没真正投递的 pending_input 行
        // 提前删掉，等于远端能替桌面「确认」一条它自己都没收到的指令。
        if (role !== "desktop") {
          ws.send(JSON.stringify({ t: "error", reason: "role_forbidden", frame: "input.ack", role }));
          return;
        }
        if (typeof payload.command_id === "string") {
          store.removePendingInput(this.sql, payload.command_id);
        }
        this.broadcastToRemotes(payload);
        return;
      case "pair.hello": {
        // H1：配对只能由远端发起；桌面反向发送会伪造一个并不存在的待配对设备。
        if (role !== "remote") {
          ws.send(JSON.stringify({ t: "error", reason: "role_forbidden", frame: payload.t, role }));
          return;
        }
        if (!this.takePairHelloSlot(ws)) return;
        const desktop = this.onlineDesktop();
        if (!desktop) {
          ws.send(JSON.stringify({ t: "error", reason: "desktop_offline" }));
          return;
        }
        // S1i3 F1（§9.5 第 235 行）：转发前在帧上盖章 origin_connection_id——绝不信手机
        // 自报。写法上先展开 payload 再覆盖同名字段，最终这个键的值只可能是 relay 自己
        // 认定的这条 socket 的 connection_id（等价于「先删手机自带的同名字段再盖」，因为
        // 无论手机是否夹带这个字段，展开顺序都保证后写的这一行赢）。同时把这条连接
        // 持久写进单行路由表（DO 休眠后内存 Map 会丢，pair.accept/pair.ready 定向投递
        // 靠这行找回目标）。
        const connectionId = safeAttachment(ws).connection_id;
        this.recordPairingRoute(connectionId);
        desktop.send(JSON.stringify({ ...payload, origin_connection_id: connectionId }));
        return;
      }
      case "pair.accept": {
        // H1：配对凭据只能由桌面签发；远端反向发送等于自行伪造授权结果。
        if (role !== "desktop") {
          ws.send(JSON.stringify({ t: "error", reason: "role_forbidden", frame: payload.t, role }));
          return;
        }
        const validation = validatePairAcceptFrame(payload);
        if (!validation.ok) {
          ws.send(JSON.stringify({
            t: "error",
            reason: "invalid_pair_accept",
            errors: validation.errors,
          }));
          return;
        }
        // S1i3 F1（§9.5 第 235 行）：撤回 broadcastToRemotes 广播——同窗多手机不互收对方
        // 的 accept。只按 pairing_routes 里记的那一行 connection_id 定向投递。
        this.deliverToPairingRoute(payload);
        return;
      }
      case "pair.done": {
        // H1：完成确认只能由收到 accept 的远端发出；桌面反向发送会伪造远端已收妥。
        if (role !== "remote") {
          ws.send(JSON.stringify({ t: "error", reason: "role_forbidden", frame: payload.t, role }));
          return;
        }
        const desktop = this.onlineDesktop();
        if (!desktop) {
          ws.send(JSON.stringify({ t: "error", reason: "desktop_offline" }));
          return;
        }
        // S1i3 F1 返工（§9.5 第 235 行「relay 转发 pair.hello / pair.done 给桌面时
        // ……并把它持久写入单行路由表」——字面管两种帧，不是只管 hello）：done 也必须
        // upsert，不能只信 hello 时写好的那一行还在指着正确的连接。两条真实后果撑住
        // 这个「必须」：
        // ① 恢复路径死：§9.5 明写 pair.done 幂等可重放是手机在 accept→ready 窗口掉线
        //   后唯一的救命路；重连后 connection_id 是握手现生成的新随机值（room-do.js
        //   的 fetch() 握手逻辑），若这里不重新写路由，路由行仍指向已断的旧连接，桌面
        //   重新产出的 ready 会在 deliverToPairingRoute 里因「目标 socket 已断」被静默
        //   丢弃，手机怎么重放 done 都拿不到 ready。
        // ② 同窗第一台被饿死：桌面在 SentAccept 态会忽略第二台手机的 hello，但那次
        //   hello 已经把路由行搬走；若这里的 done 不把路由行写回发出这条 done 的连接，
        //   ready 会投给抢路由的第二台，真正完成配对的第一台永远收不到自己的 ready。
        const connectionId = safeAttachment(ws).connection_id;
        this.recordPairingRoute(connectionId);
        desktop.send(JSON.stringify({ ...payload, origin_connection_id: connectionId }));
        return;
      }
      case "pair.ready":
        // S1i3 F1：同 pair.accept，撤回广播改定向投递。
        this.deliverToPairingRoute(payload);
        return;
      case "token.refresh":
        this.handleTokenRefresh(ws, payload);
        return;
      case "token.refresh.ok":
      case "token.refresh.fail":
        this.handleTokenRefreshReceipt(ws, payload);
        return;
      case "token.sync":
        this.handleTokenReconcile(ws, payload, false);
        return;
      case "token.reset":
        this.handleTokenReconcile(ws, payload, true);
        return;
      case "token.put":
        this.handleTokenPut(ws, payload);
        return;
      case "token.delete":
        this.handleTokenDelete(ws, payload);
        return;
      default:
        ws.send(JSON.stringify({ t: "error", reason: "unknown_frame_type" }));
    }
  }

  handleTokenPut(ws, payload) {
    if (!this.isCurrentDesktopWriter(ws)) {
      this.rejectTokenMutation(ws, payload, this.writerRejectionReason(ws));
      return;
    }
    let result;
    try {
      const entry = tokenPutFrameToEntry(payload);
      result = store.putTokenRegistryEntry(this.sql, entry, Date.now(), { cas: true });
    } catch (error) {
      const reason = tokenMutationRejectReason(error);
      if (!reason) throw error;
      result = { result: "rejected", reason };
    }
    const exceeded = result.result === "rejected" && this.recordProtocolViolation(ws);
    this.sendTokenAck(ws, payload, result);
    if (exceeded) this.closeSocketForReauthorization(ws);
  }

  handleTokenDelete(ws, payload) {
    if (!this.isCurrentDesktopWriter(ws)) {
      this.rejectTokenMutation(ws, payload, this.writerRejectionReason(ws));
      return;
    }
    let result;
    try {
      if (!Number.isSafeInteger(payload.generation) || payload.generation <= 0) {
        throw new TypeError("invalid token subject generation");
      }
      if (payload.close !== undefined && typeof payload.close !== "boolean") {
        throw new TypeError("invalid close flag");
      }
      result = store.putTokenRegistryEntry(this.sql, {
        subject: payload.subject,
        generation: payload.generation,
        state: "revoked",
        scope: null,
        aliases: [],
      }, Date.now(), { cas: true });
    } catch (error) {
      const reason = tokenMutationRejectReason(error);
      if (!reason) throw error;
      result = { result: "rejected", reason };
    }
    let exceeded = false;
    if (result.result === "rejected") {
      exceeded = this.recordProtocolViolation(ws);
    } else if (payload.close === true) {
      this.closeSocketsForRevokedSubject(payload.subject);
    }
    this.sendTokenAck(ws, payload, result);
    if (exceeded) this.closeSocketForReauthorization(ws);
  }

  // ---- S1i2 §9.6 第 246 行：refresh 三帧成套的手机→relay 半边 ----
  // 身份=attachment（「手机 token.refresh 到达 → 盖章身份」）：subject/
  // request_generation 绝不信手机自报，一律读已通过 authorizeInboundSocket
  // 再授权闸的 attachment（到这里时 attachment.generation 已由该闸保证等于
  // subject 当前 generation）。
  handleTokenRefresh(ws, payload) {
    const attachment = safeAttachment(ws);
    const shapeError = tokenRefreshShapeError(payload);
    if (shapeError) {
      this.rejectTokenRefresh(ws, shapeError);
      return;
    }
    if (!attachment.subject) {
      // legacy dev remote（S1j 前遗留、无 subject 可盖章身份）明确拒绝，不
      // 假装能处理——§9.6 的整套投递谓词都要靠一个真实 subject 撑住。
      this.rejectTokenRefresh(ws, "subject_required");
      return;
    }

    const existing = store.getRefreshRequest(this.sql, payload.request_id);
    const isResend = existing != null && existing.subject === attachment.subject;
    // §9.8 6/min 主桶；resend 不计主配额，但 R4 补一道独立宽松桶（见常量注释）。
    if (isResend) {
      if (!this.takeRefreshResendSlot(ws)) return;
    } else if (!this.takeRefreshRequestSlot(ws)) {
      return;
    }

    const desktop = this.onlineDesktopForEpoch(store.getCurrentEpoch(this.sql));
    if (!desktop) {
      ws.send(JSON.stringify({ t: "error", reason: "desktop_offline" }));
      return;
    }

    const requestGeneration = Number(attachment.generation);
    const upsert = store.upsertRefreshRequest(this.sql, {
      requestId: payload.request_id,
      subject: attachment.subject,
      requestGeneration,
      connectionId: attachment.connection_id,
      deadline: Date.now() + REFRESH_REQUEST_TTL_MS,
      // R3（§9.8 第 263 行）：休眠唤醒后的 webSocketMessage 拿不到原始
      // Request，per-IP 计费一律用 upgrade 时写进 attachment 的 key，不现取。
      ipBucketKey: attachment.ip_bucket_key ?? null,
    });
    if (!upsert.ok) {
      this.rejectTokenRefresh(ws, upsert.reason);
      return;
    }

    desktop.send(JSON.stringify({
      t: "token.refresh.forward",
      request_id: payload.request_id,
      subject: attachment.subject,
      request_generation: requestGeneration,
      ct: payload.ct,
      n: payload.n,
    }));
    void this.scheduleNextTokenAlarm();
  }

  rejectTokenRefresh(ws, reason) {
    const exceeded = this.recordProtocolViolation(ws);
    ws.send(JSON.stringify({ t: "error", reason, frame: "token.refresh" }));
    if (exceeded) this.closeSocketForReauthorization(ws);
  }

  // pair.hello 同款 per-socket 滑窗设施（S1e 既有模式，非新造）：窗口过期即
  // 重置计数；攒满即回错误 + 关连接，聚合计数走既有 recordProtocolViolation。
  takeRefreshRequestSlot(ws, now = Date.now()) {
    const attachment = safeAttachment(ws);
    if (!Number.isSafeInteger(attachment.refresh_window_started_at) ||
        now >= attachment.refresh_window_started_at + REFRESH_REQUEST_WINDOW_MS) {
      attachment.refresh_window_started_at = now;
      attachment.refresh_attempts = 0;
    }
    if (Number(attachment.refresh_attempts) >= REFRESH_REQUEST_LIMIT) {
      this.recordProtocolViolation(ws);
      try {
        ws.send(JSON.stringify({ t: "error", reason: "token_refresh_rate_limited" }));
      } finally {
        this.closeSocketForReauthorization(ws);
      }
      return false;
    }
    attachment.refresh_attempts = Number(attachment.refresh_attempts) + 1;
    this.assertAttachmentBudget(attachment);
    ws.serializeAttachment(attachment);
    return true;
  }

  // R4（§9.6/§9.8 v1.8.5）：resend 独立宽松桶——与 takeRefreshRequestSlot 同款
  // 滑窗设施，但用另一组 attachment 字段，不共享计数（否则一次 resend 就会
  // 提前耗尽本该留给新请求的 6/min 主配额，二者语义不同不能混用同一个桶）。
  takeRefreshResendSlot(ws, now = Date.now()) {
    const attachment = safeAttachment(ws);
    if (!Number.isSafeInteger(attachment.refresh_resend_window_started_at) ||
        now >= attachment.refresh_resend_window_started_at + REFRESH_RESEND_WINDOW_MS) {
      attachment.refresh_resend_window_started_at = now;
      attachment.refresh_resend_attempts = 0;
    }
    if (Number(attachment.refresh_resend_attempts) >= REFRESH_RESEND_LIMIT) {
      this.recordProtocolViolation(ws);
      try {
        ws.send(JSON.stringify({ t: "error", reason: "token_refresh_resend_rate_limited" }));
      } finally {
        this.closeSocketForReauthorization(ws);
      }
      return false;
    }
    attachment.refresh_resend_attempts = Number(attachment.refresh_resend_attempts) + 1;
    this.assertAttachmentBudget(attachment);
    ws.serializeAttachment(attachment);
    return true;
  }

  // ---- S1i2 §9.6 第 246 行：refresh 三帧成套的桌面→relay→手机半边 ----
  // ok/fail 的形状校验就地做（桌面→relay 走 desktop 入站矩阵，到这里时
  // epoch/registry_ready 前置闸已经过——见 webSocketMessage 顶部 stale_epoch
  // 与 sync_required 两道闸，desktop 写者身份已由它们保证，不重复判）。
  handleTokenRefreshReceipt(ws, payload) {
    const shapeError = tokenRefreshReceiptShapeError(payload);
    if (shapeError) {
      const exceeded = this.recordProtocolViolation(ws);
      ws.send(JSON.stringify({ t: "error", reason: shapeError, frame: payload.t }));
      if (exceeded) this.closeSocketForReauthorization(ws);
      return;
    }
    this.deliverRefreshReceipt(payload);
  }

  /**
   * §9.6 第 246 行投递谓词，逐条实现：
   *   ① 房 live
   *   ② subject active
   *   ③ 回执.subject == 请求行.subject
   *   ④ 回执.generation == subject 当前 generation（轮换后新代·不要求等于
   *      request_generation；fail 帧结构上不带 generation，天然豁免本条）
   *   ⑤ now < deadline
   *   ⑥ 目标 = 请求行 connection_id（已断则丢弃·手机走别名重放/resend 恢复）
   * 投完/过期删行。**自有谓词，故意绕过 canDeliverOutbound**——S1i1 遗留
   * （桌面幂等重放不等 put 的 ack 就直接发回执）使得回执到达时手机 socket
   * 的 attachment 章可能还是旧代；canDeliverOutbound 的 isOfficialAttachmentLive
   * 会先把这条 socket 判死、回执因此永远送不到，每次轮换都被迫走「断线 +
   * prev 重连 + journal 重放」的慢路径。这里独立复核 token_subjects 的当前
   * 权威 generation（不信 attachment 缓存的旧值），是这条路径上唯一防线：
   * 只要④成立就投，不管发送这条回执的桌面连接此刻的 epoch/attachment 是否
   * 仍与目标 socket 的旧 attachment 一致。
   */
  deliverRefreshReceipt(payload, now = Date.now()) {
    // R5.2：assertRoomLive 前置——与「assertRoomLive 无路由例外」的写法纪律
    // 对齐（fetch/webSocketMessage/webSocketClose/alarm/构造器一律先判 live
    // 再摸 DB），本函数之前是先读行再判 live，顺序反了。
    if (!this.assertRoomLive()) return; // ①

    const row = store.getRefreshRequest(this.sql, payload.request_id);
    if (!row) return; // 未知/已消费的 request_id：安全丢弃，不是本谓词的六条之一

    const subject = store.getTokenSubject(this.sql, row.subject);
    if (!subject || subject.state !== "active") return; // ②

    if (payload.subject !== row.subject) return; // ③

    if (payload.t === "token.refresh.ok" &&
        Number(payload.generation) !== Number(subject.generation)) {
      return; // ④
    }

    if (!(now < Number(row.deadline))) { // ⑤
      store.deleteRefreshRequest(this.sql, row.request_id);
      return;
    }

    const target = this.ctx.getWebSockets().find(
      (candidate) => safeAttachment(candidate).connection_id === row.connection_id
    );
    if (!target) return; // ⑥ 已断则丢弃·不删行——手机走别名重放/resend 重绑恢复
    // R1（双路审）：真实 Cloudflare 运行时里，close 握手期间 getWebSockets()
    // 仍可能返回一条正处于 CLOSING 的 socket——它已经被 canDeliverOutbound
    // 判过期而调了 closeSocketForReauthorization()，但 Hibernation API 不保证
    // 那一刻它就从 getWebSockets() 里消失。此刻投递等于把回执塞给正在离场的
    // 连接，而「投完删行」还会把这份回执从 refresh_requests 里删掉——手机走
    // prev 别名/resend 的恢复路径就再也捞不回它。同 ⑥ 语义：readyState 非
    // OPEN 时也按 ⑥ 丢弃且不删行。选 readyState 检查而不是 try/catch send
    // 失败：WebSocket 规范里 `send()` 在 CLOSING/CLOSED 状态下是**静默丢弃**、
    // 不抛异常（MDN：「If you call send() when the connection is in the
    // CLOSING or CLOSED states, the browser will silently discard the
    // data」），try/catch 在这个场景下根本捕不到东西，只有先查 readyState
    // 才能在投递前发现——@cloudflare/workers-types 的 WebSocket 接口本就有
    // `readyState: number`（WebSocketPair 两端都是 WebSocket 类型），
    // Hibernation server socket 上这个属性存在。
    if (Number(target.readyState) !== 1 /* WebSocket.OPEN */) return;
    // R5.1：对齐 canDeliverOutbound:1318 的纵深检查——不是本谓词的六条之一，
    // 是额外一道防线。目标连接正因 §9.8 并发上限被清退（enforceSubjectSocketLimit
    // 已标记但可能还没真正 close 完成），此刻投递等于把回执塞给一个正在离场
    // 的连接；同 ⑥ 不删行，交给之后的重试/resend 走另一个存活连接。
    if (safeAttachment(target).subject_limit_closed === true) return;

    target.send(JSON.stringify(payload));
    store.deleteRefreshRequest(this.sql, row.request_id); // 投完删行
  }

  handleTokenReconcile(ws, payload, reset) {
    if (!this.isCurrentDesktopWriter(ws)) {
      this.rejectStaleDesktopFrame(ws);
      return;
    }
    if (!Number.isSafeInteger(payload.revision) || payload.revision <= 0) {
      ws.send(JSON.stringify({ t: "error", reason: "revision_required", frame: payload.t }));
      return;
    }
    if (!Array.isArray(payload.entries)) {
      ws.send(JSON.stringify({ t: "error", reason: "entries_required", frame: payload.t }));
      return;
    }
    if (payload.entries.length > SYNC_ENTRY_LIMIT) {
      this.recordProtocolViolation(ws);
      const reason = reset ? "reset_entries_too_many" : "sync_entries_too_many";
      try {
        ws.send(JSON.stringify({ t: "error", reason, frame: payload.t }));
      } finally {
        this.closeSocketForReauthorization(ws);
      }
      return;
    }

    const entries = payload.entries.map((entry) => {
      try {
        return tokenPutFrameToEntry(entry);
      } catch {
        return { invalid: true, subject: entry?.subject };
      }
    });
    const result = store.reconcileTokenRegistry(this.sql, {
      revision: payload.revision,
      entries,
      reset,
    }, Date.now());

    for (const subject of new Set(result.revokedSubjects)) {
      this.closeSocketsForRevokedSubject(subject);
    }
    ws.send(JSON.stringify({
      t: "token.sync.ack",
      revision: payload.revision,
      relay_high_water: result.relayHighWater,
    }));

    const attachment = safeAttachment(ws);
    if (attachment.registry_ready === true) return;
    attachment.registry_ready = true;
    delete attachment.registry_sync_deadline;
    this.assertAttachmentBudget(attachment);
    ws.serializeAttachment(attachment);
    this.desktopHello(ws, attachment.epoch);
    this.flushPendingInputTo(ws);
    this.broadcastPresence("desktop", "online", ws);
    void this.scheduleNextTokenAlarm();
  }

  isCurrentDesktopWriter(ws) {
    const attachment = safeAttachment(ws);
    return attachment.role === "desktop" &&
      attachment.scope === "desktop" &&
      Number(attachment.epoch) === store.getCurrentEpoch(this.sql);
  }

  writerRejectionReason(ws) {
    const attachment = safeAttachment(ws);
    if (attachment.role === "desktop" && attachment.scope === "desktop") return "stale_epoch";
    return "writer_forbidden";
  }

  rejectTokenMutation(ws, payload, reason) {
    const exceeded = this.recordProtocolViolation(ws);
    this.sendTokenAck(ws, payload, { result: "rejected", reason });
    if (exceeded) this.closeSocketForReauthorization(ws);
  }

  sendTokenAck(ws, payload, result) {
    const ack = {
      t: "token.ack",
      subject: typeof payload.subject === "string" ? payload.subject : null,
      generation: Number.isSafeInteger(payload.generation) ? payload.generation : null,
      result: result.result,
    };
    if (result.reason) ack.reason = result.reason;
    ws.send(JSON.stringify(ack));
  }

  closeSocketsForRevokedSubject(subject) {
    for (const socket of this.ctx.getWebSockets()) {
      if (safeAttachment(socket).subject !== subject) continue;
      try {
        socket.send(JSON.stringify({ t: "error", reason: "device_revoked" }));
      } finally {
        this.closeSocketForReauthorization(socket);
      }
    }
  }

  // ---- 重连补发 ----
  // 桌面不走 replayTo 的里程碑补发，握手后需单独同步新 epoch/headSeq（§6.4 v1.4）。
  desktopHello(ws, epoch) {
    ws.send(JSON.stringify({ t: "replay.head", epoch, headSeq: store.headSeq(this.sql) }));
  }

  replayTo(ws, lastSeq) {
    const rows = store.replaySince(this.sql, lastSeq);
    const headSeq = store.headSeq(this.sql);
    const epoch = store.getCurrentEpoch(this.sql);
    const roomId = store.getMeta(this.sql, "room_id");

    const head = { t: "replay.head", epoch, headSeq };
    if (!this.canDeliverOutbound(ws, head)) return;
    ws.send(JSON.stringify(head));

    for (const row of rows) {
      const envelope = {
        v: PROTOCOL_VERSION,
        room: roomId,
        epoch: row.epoch,
        kind: row.kind,
        session: row.session,
        command_id: null, // 里程碑不走 input 通道，command_id 恒无意义
        seq: row.seq,
        client_msg_id: row.client_msg_id ?? null,
        ct: row.ct,
        n: row.n,
        ts: row.ts,
      };
      if (!this.canDeliverOutbound(ws, envelope)) return;
      ws.send(JSON.stringify(envelope));
    }
  }

  // ---- 桌面重连：把暂存的 input 排空（FIFO）+ 清理过期项 ----
  flushPendingInputTo(desktopWs) {
    const { deliverable, expired } = store.drainDeliverableInput(this.sql, Date.now());

    for (const row of deliverable) {
      if (!store.isPendingInputAuthorized(this.sql, row)) expired.push(row);
    }

    for (const row of expired) {
      store.removePendingInput(this.sql, row.command_id);
      this.broadcastToRemotes({ t: "input.expired", command_id: row.command_id });
    }

    for (const row of deliverable) {
      if (expired.includes(row)) continue;
      // row.envelope 已经是入队时存下的、含 command_id 的单层信封 JSON 字符串
      // ——原样转发，不需要 parse 再包一层。
      desktopWs.send(row.envelope);
    }
  }

  // ---- G8 R4（双路审 fix_required④）：handleInput 入队前的死行清扫 ----
  // 同款 input.expired 广播语义（照既有 flushPendingInputTo 的做法），但
  // 不核 isPendingInputAuthorized 撤销分支——那是桌面上线交付时才需要核的
  // 额外条件（订阅撤销），入队前这一步只关心纯 TTL 过期，两者是不同的
  // 「过期」概念，不能混用同一段逻辑。
  //
  // G8 三审 fix_required（codex xhigh 差量审）R3：不再复用
  // drainDeliverableInput——这条路径现在每次 handleInput 入队前都会跑一遍
  // （高频），drainDeliverableInput 是"SELECT * ... 把整表（含大字段
  // envelope）搬进 JS"给桌面上线那条低频路径用的，两条路径的读取代价不该
  // 混在一起；改用 store.deleteExpiredPendingInput——只按 expires_at 索引
  // 取 command_id、按同一谓词批量删，全程不碰 envelope 列（那条路径本身
  // 不动，仍服务 flushPendingInputTo）。
  purgeExpiredPendingInput(now = Date.now()) {
    const expiredCommandIds = store.deleteExpiredPendingInput(this.sql, now);
    for (const commandId of expiredCommandIds) {
      this.broadcastToRemotes({ t: "input.expired", command_id: commandId });
    }
  }

  // ---- 小工具 ----
  assertRoomLive() {
    return store.isRoomLive(this.sql);
  }

  closeSocketForTombstone(ws) {
    try {
      ws.close(TOMBSTONE_CLOSE_CODE, TOMBSTONE_CLOSE_REASON);
    } catch {
      // Socket 可能已经进入 close 回调；生命周期真相仍已由 sentinel 拒绝。
    }
  }

  closeAllSockets() {
    for (const ws of this.ctx.getWebSockets()) {
      this.closeSocketForTombstone(ws);
    }
  }

  rejectOversizedFrame(ws) {
    this.recordProtocolViolation(ws);
    try {
      ws.send(JSON.stringify({ t: "error", reason: "frame_too_large" }));
    } finally {
      try {
        ws.close(1009, "frame_too_large");
      } catch {
        // 已关闭连接无需二次处置；尺寸闸已在 parse 前完成。
      }
    }
  }

  rejectStaleDesktopFrame(ws) {
    const currentEpoch = store.getCurrentEpoch(this.sql);
    try {
      ws.send(JSON.stringify({ t: "error", reason: "stale_epoch", currentEpoch }));
    } finally {
      this.closeSocketForReauthorization(ws);
    }
  }

  closeDesktopForSyncTimeout(ws) {
    try {
      ws.send(JSON.stringify({ t: "error", reason: "sync_timeout" }));
    } finally {
      try {
        ws.close(1008, "sync_timeout");
      } catch {
        // alarm 与 close 回调可竞态；只要该连接不再成为 selector 候选即可。
      }
    }
  }

  onlineDesktop() {
    return this.onlineDesktopForEpoch(store.getCurrentEpoch(this.sql));
  }

  broadcastReplacedDesktopOffline(currentEpoch) {
    const replacedReadyDesktop = this.ctx.getWebSockets("desktop").some((ws) => {
      const attachment = safeAttachment(ws);
      return attachment.role === "desktop" && attachment.scope === "desktop" &&
        attachment.registry_ready === true &&
        Number(attachment.epoch) < Number(currentEpoch);
    });
    if (replacedReadyDesktop) this.broadcastPresence("desktop", "offline");
  }

  onlineDesktopForEpoch(currentEpoch) {
    return this.ctx.getWebSockets("desktop").find((ws) => {
      const attachment = safeAttachment(ws);
      return Number(attachment.epoch) === Number(currentEpoch) && attachment.registry_ready === true;
    }) ?? null;
  }

  async rejectUpgradeAuthentication(ipBucketKey, hashPrefix, now = Date.now()) {
    const fineKey = `${ipBucketKey}:${hashPrefix}`;
    const limited = bucketAtLimit(this.upgradeFineBuckets, fineKey, UPGRADE_FINE_LIMIT, now) ||
      bucketAtLimit(this.upgradeCoarseBuckets, ipBucketKey, UPGRADE_COARSE_LIMIT, now);
    recordBucketHit(this.upgradeFineBuckets, fineKey, now);
    recordBucketHit(this.upgradeCoarseBuckets, ipBucketKey, now);
    // SEC-3：失败 upgrade 是「对未认领房的实例化」之一（brief 原话例子）——
    // 这条路径从不会走到 fetch() 里握手成功后的既有 scheduleNextTokenAlarm()
    // 调用（:333 一线），是它唯一的落点，武装/复算固定回收 alarm。owner 非
    // null（已 claim）时不进——已 claim 房不会被这里重排回收 alarm（与 alarm()
    // 回收枝、scheduleNextTokenAlarm 第四类候选同一个误杀防线不变量）。放在
    // 构造响应之前/之后皆可，这里选择错误响应仍照常返回、不受影响。
    if (store.getRoomState(this.sql).owner_credential_hash == null) {
      await this.scheduleNextTokenAlarm(now);
    }
    return new Response(limited ? "rate limited" : "unauthorized", { status: limited ? 429 : 401 });
  }

  takePairHelloSlot(ws, now = Date.now()) {
    const attachment = safeAttachment(ws);
    if (!Number.isSafeInteger(attachment.pair_hello_window_started_at) ||
        now >= attachment.pair_hello_window_started_at + PAIR_HELLO_WINDOW_MS) {
      attachment.pair_hello_window_started_at = now;
      attachment.pair_hello_attempts = 0;
    }
    if (Number(attachment.pair_hello_attempts) >= PAIR_HELLO_LIMIT) {
      this.recordProtocolViolation(ws);
      try {
        ws.send(JSON.stringify({ t: "error", reason: "pair_hello_rate_limited" }));
      } finally {
        this.closeSocketForReauthorization(ws);
      }
      return false;
    }
    attachment.pair_hello_attempts = Number(attachment.pair_hello_attempts) + 1;
    this.assertAttachmentBudget(attachment);
    ws.serializeAttachment(attachment);
    return true;
  }

  // G8 R1（双路审 fix_required①）：per-subject SQL 固定窗——取代原先分开
  // 手写的 attachment 版 takeInputRateSlot/takeControlRateSlot。旧版把窗口/
  // 计数存在 socket 的 attachment 上，被盗的已配对手机完全掌控自己何时
  // 断线重连，断了重连一次桶就清零，形同虚设；这版状态搬进
  // message_rate_limits 表（room-store.js takeMessageRateSlot），同 subject
  // 的多个并发 socket 共享同一行，跨 socket/跨重连/跨休眠不丢。input/
  // control 复用同一份实现，只是 channel/limit/reason 三个参数不同——旧版
  // 分开手写两份是因为各自要单独存取不同的 attachment 字段，状态搬进 SQL
  // 后两条路径的逻辑已经完全一致，再手写两份是纯重复。
  takeSubjectChannelRateSlot(ws, envelope, { channel, limit, windowMs, reason }, now = Date.now()) {
    const subject = safeAttachment(ws).subject;
    // 理论不存在：authorizeInboundSocket 已对没有 subject 的连接 fail-closed
    // （S1ja F2 起），这条分支到不了这里；万一未来前置闸变了，fail-open 不
    // 新增一个判死点，让消息路由本身继续走，不因为限速设施本身的假设被
    // 打破就连累到无关的功能。
    if (!subject) return true;

    const result = store.takeMessageRateSlot(this.sql, { subject, channel, limit, windowMs, now });
    if (result.allowed) return true;

    // G8 R3（双路审 fix_required③）：只在本窗口第一次超限时计一次协议
    // 违例——把「这个 subject 本窗口在持续超速」这一个事实映射成 1 次
    // 违例，不是「超速的帧数」：手快刷屏一个窗口哪怕连发几十条被拒的帧，
    // 也只吃 1 strike，不会被这一个窗口单独攒到 8 次踢连接阈值。
    let exceeded = false;
    if (result.firstExceedThisWindow) {
      exceeded = this.recordProtocolViolation(ws);
    }
    const error = { t: "error", reason, frame: channel };
    // G8 R5：带 command_id——input/control 的 envelope 校验保证它非空，
    // 手机端要能把这条限速拒绝跟自己发出的哪条帧对上号。
    if (envelope && typeof envelope.command_id === "string") error.command_id = envelope.command_id;
    ws.send(JSON.stringify(error));
    // G8 R3：踢连接时用独立的 close reason——不能复用
    // closeSocketForReauthorization 的 "token_reauthorization_failed"，那个
    // reason 会让手机端把「发太快被限速」误判成「凭据坏了」去走重新配对
    // 流程；这里的真实原因只是节流，正常退避重连就该恢复。
    if (exceeded) this.closeSocketForMessageRateLimit(ws);
    return false;
  }

  // G8 R2（双路审 fix_required②）：per-IP 粗桶——结构照 upgrade 粗桶，复用
  // 同一对 bucketAtLimit/recordBucketHit 内存 Map 原语（不新造第二套滑窗
  // 实现）。key 用 attachment.ip_bucket_key（S1i2 R3 落的字段，upgrade 时
  // 握手已恒写入）；没有这个字段的旧连接（理论不存在——S1i2 起的握手路径
  // 必带）fail-open 跳过本桶，不阻断消息路由本身（宁可漏放这一条粗防线，
  // 也不能让一个字段缺失变成「谁都发不出消息」的可用性事故）。
  //
  // 超限只拒不踢（opus B1 定罪：旧版超限即踢会让共享同一个 ip_bucket_key
  // 的无辜邻居设备被同房作恶者连累下线）——recordProtocolViolation(null)
  // 只累房间聚合计数供审计，不挂到任何一条具体 socket 上、不影响它自己的
  // 8 次踢连接阈值。
  //
  // G8 三审 fix_required R1：Map 真硬上限——旧版只在 size > 4096 之后才扫，
  // 且只清"已过期"的条目；如果 4097 个不同 key 全在同一个活跃窗口内（谁都
  // 没过期），这一扫什么都清不掉，Map 从此永久停在"超过阈值"状态，此后
  // *每一帧*都要付一次 O(n) 全表扫描，且新 key 还在继续插入——持续换 IP
  // 攻击下趋向 O(n²)。改：只在「这是一把从没见过的新 key，且当前 size 已经
  // 顶到上限」时才触发一次性的过期清扫；清完仍顶着上限——fail-closed 直接
  // 拒绝这一帧（同款 ip_message_rate_limited 错误帧），绝不为了腾地方去踢
  // 掉正在计数的活跃桶（那样等于给"满员"状态本身开一个新口子：攻击者只要
  // 开够多不同 IP，就能把别人的活跃桶挤掉，白得一次"免限速"窗口）。已经在
  // Map 里的 key（不管是不是这一批新插的）永远只走下面的正常 check+record，
  // 不会因为 Map 满而被牵连。
  takeIpMessageSlot(ws, frameType, commandId, now = Date.now()) {
    const ipBucketKey = safeAttachment(ws).ip_bucket_key;
    if (typeof ipBucketKey !== "string" || ipBucketKey.length === 0) return true;

    const isNewKey = !this.ipMessageBuckets.has(ipBucketKey);
    if (isNewKey && this.ipMessageBuckets.size >= IP_MESSAGE_BUCKET_MAX_ENTRIES) {
      evictExpiredBuckets(this.ipMessageBuckets, now, IP_MESSAGE_RATE_WINDOW_MS);
      if (this.ipMessageBuckets.size >= IP_MESSAGE_BUCKET_MAX_ENTRIES) {
        this.recordProtocolViolation(null);
        const capError = { t: "error", reason: "ip_message_rate_limited", frame: frameType };
        if (typeof commandId === "string") capError.command_id = commandId;
        ws.send(JSON.stringify(capError));
        return false;
      }
    }

    const limited = bucketAtLimit(
      this.ipMessageBuckets, ipBucketKey, IP_MESSAGE_RATE_LIMIT, now, IP_MESSAGE_RATE_WINDOW_MS
    );
    recordBucketHit(this.ipMessageBuckets, ipBucketKey, now, IP_MESSAGE_RATE_WINDOW_MS);
    if (limited) {
      this.recordProtocolViolation(null);
      const error = { t: "error", reason: "ip_message_rate_limited", frame: frameType };
      // G8 R5：中央挂点这时候还没跑到 validateEnvelope，拿到的是未经校验的
      // 原始 payload——只有它自己真的带了字符串形态的 command_id（input/
      // control 这类帧）才回带；presence/pair.hello/token.refresh 这类帧本来
      // 就没有 command_id，不该在错误帧里绑一个不存在的字段。
      if (typeof commandId === "string") error.command_id = commandId;
      ws.send(JSON.stringify(error));
      return false;
    }
    return true;
  }

  // G8 R3：per-subject 消息限速攒够 8 次协议违例后的专属踢连接——见
  // MESSAGE_RATE_LIMIT_CLOSE_REASON 定义处注释（为什么不能复用
  // closeSocketForReauthorization）。
  closeSocketForMessageRateLimit(ws) {
    try {
      ws.close(MESSAGE_RATE_LIMIT_CLOSE_CODE, MESSAGE_RATE_LIMIT_CLOSE_REASON);
    } catch {
      // 同 closeSocketForReauthorization：close/alarm 可能与当前投递竞态。
    } finally {
      this.flushProtocolViolations();
    }
  }

  enforceSubjectSocketLimit(subject) {
    const sockets = this.ctx.getWebSockets()
      .filter((ws) => {
        const attachment = safeAttachment(ws);
        return attachment.subject === subject &&
          attachment.subject_limit_closed !== true &&
          this.isOfficialAttachmentLive(attachment, Date.now());
      })
      .sort((left, right) =>
        Number(safeAttachment(left).connectedAt || 0) - Number(safeAttachment(right).connectedAt || 0)
      );
    if (sockets.length < SUBJECT_SOCKET_LIMIT) return;
    const oldest = sockets[0];
    const attachment = safeAttachment(oldest);
    attachment.subject_limit_closed = true;
    try {
      oldest.serializeAttachment(attachment);
      oldest.send(JSON.stringify({ t: "error", reason: "subject_socket_limit" }));
    } finally {
      this.closeSocketForReauthorization(oldest);
    }
  }

  broadcastRaw(payload, excludeWs) {
    const text = JSON.stringify(payload);
    for (const ws of this.ctx.getWebSockets()) {
      if (ws === excludeWs) continue;
      if (this.canDeliverOutbound(ws, payload)) ws.send(text);
    }
  }

  broadcastToRemotes(payload) {
    const text = JSON.stringify(payload);
    for (const ws of this.ctx.getWebSockets("remote")) {
      if (this.canDeliverOutbound(ws, payload)) ws.send(text);
    }
  }

  // S1i3 F1（§9.5 第 235 行）：pair.accept / pair.ready 定向投递——只发给 pairing_routes
  // 里记的那一条 connection_id（最近一次 pair.hello/pair.done 的发起者），不再
  // broadcastToRemotes 广播给房间内全部远端。复用 deliverRefreshReceipt 按 connection_id
  // 查 socket 的写法。没有路由行（从未发生过配对）或目标连接已断——安全丢弃，不是错误：
  // 配对本就可能因手机中途断线而失败，注册表那条 pairing 授权自会在 300s TTL 后自然过期。
  deliverToPairingRoute(payload) {
    // S1i3 K3.1：assertRoomLive 前置——与 deliverRefreshReceipt 的既有纪律（:957 摸 DB
    // 前先判 live）对齐；「assertRoomLive 无路由例外」，摸 DB 的方法各自独立判 live，
    // 不依赖调用方（当前唯一调用方 webSocketMessage 已经判过）不出错。
    if (!this.assertRoomLive()) return;
    const connectionId = store.getPairingRoute(this.sql);
    if (!connectionId) return;
    // S1i3 K3.2：目标恒是发起配对的那条 remote（手机）连接，收窄成按 "remote" tag 扫，
    // 不再像之前那样囫囵扫全量（含 desktop）——跟已撤掉的 broadcastToRemotes 用
    // getWebSockets("remote") 是同一层纵深防线，缩小误投面。
    const target = this.ctx.getWebSockets("remote").find(
      (candidate) => safeAttachment(candidate).connection_id === connectionId
    );
    if (!target) return;
    if (!this.canDeliverOutbound(target, payload)) return;
    target.send(JSON.stringify(payload));
  }

  // S1i3 K3.1：pair.hello / pair.done 转发前落路由行都要走这里——与 deliverToPairingRoute
  // 的既有纪律对齐（摸 DB 前先判 live），也让「这张表唯一的写口」只有一处，不给未来任何
  // 新调用点留「忘了先判 live 就写库」的空子。
  recordPairingRoute(connectionId) {
    if (!this.assertRoomLive()) return;
    store.setPairingRoute(this.sql, connectionId);
  }

  broadcastPresence(role, event, excludeWs) {
    this.broadcastRaw({ t: "presence", role, event, ts: Date.now() }, excludeWs);
  }

  authorizeInboundSocket(ws, attachment, now = Date.now()) {
    if (attachment.subject_limit_closed === true) return false;
    if (attachment.scope === "desktop" && attachment.role !== "desktop") {
      const exceeded = this.recordProtocolViolation(ws);
      ws.send(JSON.stringify({ t: "error", reason: "role_forbidden", role: attachment.role ?? null }));
      if (exceeded) this.closeSocketForReauthorization(ws);
      return false;
    }
    if (!INBOUND_SCOPE_MATRIX[attachment.scope]) {
      // scope 缺失（S1d 之前的老 attachment）或不在矩阵里（未来新 scope 的
      // 连接撞上旧代码）都没有任何可放行的帧型——留着这条连接只能让它一直
      // 空转重试，直接 close 让客户端带新凭据重连。
      this.recordProtocolViolation(ws);
      try {
        ws.send(JSON.stringify({ t: "error", reason: "role_forbidden", role: attachment.role ?? null }));
      } finally {
        this.closeSocketForReauthorization(ws);
      }
      return false;
    }
    // desktop 的对称权威闸仍是各 handler 的 epoch 检查（S1a）。
    if (attachment.role === "desktop" && attachment.scope === "desktop") return true;
    // S1ja F2：legacy dev valid_tokens 的过渡期豁免已撤——没有 subject 行的
    // remote/pairing/refresh socket 只可能来自已删除的后门（room_meta 存量行
    // 也随 F2 迁移一并清空），永不过期、不可吊销，是一条永久后门；现在跟任何
    // 其它没有真实 subject 的 attachment 一样，落进下面这条 fail-closed 分支。
    if (!attachment.subject || !this.isOfficialAttachmentLive(attachment, now)) {
      const subject = attachment.subject ? store.getTokenSubject(this.sql, attachment.subject) : null;
      const reason = subject && Number(subject.generation) !== Number(attachment.generation)
        ? "stale_generation"
        : "reauthorization_failed";
      try {
        ws.send(JSON.stringify({ t: "error", reason }));
      } finally {
        this.closeSocketForReauthorization(ws);
      }
      return false;
    }
    return true;
  }

  isOfficialAttachmentLive(attachment, now = Date.now()) {
    const subject = store.getTokenSubject(this.sql, attachment.subject);
    if (!subject || subject.state !== "active") return false;
    if (Number(subject.generation) !== Number(attachment.generation)) return false;
    const alias = store.getTokenAlias(
      this.sql,
      attachment.subject,
      attachment.kind
    );
    if (!alias || Number(alias.generation) !== Number(attachment.alias_generation)) return false;
    if (attachment.kind === "current") {
      if (Number(attachment.access_expires) !== Number(alias.access_expires) ||
          Number(attachment.valid_until) !== Number(alias.valid_until)) {
        return false;
      }
    } else if (attachment.kind === "prev") {
      if (Number(attachment.valid_until) !== Number(alias.valid_until)) return false;
    } else {
      return false;
    }
    if (attachment.scope === "refresh") return now < Number(attachment.valid_until);
    if (["remote", "pairing"].includes(attachment.scope)) {
      return attachment.kind === "current" && now < Number(attachment.access_expires);
    }
    return false;
  }

  async scheduleNextTokenAlarm(now = Date.now()) {
    if (typeof this.ctx.storage.setAlarm !== "function") return;
    let nearest = null;
    for (const ws of this.ctx.getWebSockets()) {
      const attachment = safeAttachment(ws);
      if (attachment.role === "desktop" && attachment.scope === "desktop" && attachment.registry_ready !== true) {
        const deadline = Number(attachment.registry_sync_deadline);
        if (Number.isSafeInteger(deadline) && (nearest == null || deadline < nearest)) nearest = deadline;
        continue;
      }
      if (!attachment.subject || !this.isOfficialAttachmentLive(attachment, now)) continue;
      const expires = attachment.scope === "refresh"
        ? Number(attachment.valid_until)
        : Number(attachment.access_expires);
      if (Number.isSafeInteger(expires) && expires > now && (nearest == null || expires < nearest)) {
        nearest = expires;
      }
    }
    // P2-3：refresh_requests.deadline 是第三类待办时刻，与上面两类（registry
    // sync 超时 / token 过期）统一进同一个 min 计算，一处算、一处设——不再是
    // 「最后 setAlarm 的那类独占」，避免二者互踩。
    const refreshDeadline = store.nextRefreshRequestDeadline(this.sql, now);
    if (refreshDeadline != null && (nearest == null || refreshDeadline < nearest)) {
      nearest = refreshDeadline;
    }
    // SEC-3：未认领空房固定回收截止——第四类候选。owner 非 null（已 claim）
    // 时不参与这个 min：已 claim 房绝不会被这里排一个回收 alarm（误杀防线，
    // 与 alarm() 回收枝的硬门同一个不变量）。createdAt 理论上不该是 null
    // （initRoomStateSentinel 无条件回填，构造器无条件调它），这里仍防御性
    // 兜底——读不到就不排这个候选，不猜一个时刻。
    const unclaimedState = store.getRoomState(this.sql);
    if (unclaimedState.owner_credential_hash == null && unclaimedState.created_at != null) {
      const reclaimAt = Number(unclaimedState.created_at) + UNCLAIMED_RECLAIM_MS;
      if (nearest == null || reclaimAt < nearest) nearest = reclaimAt;
    }
    if (nearest != null) {
      // F3（T4 修复轮·整盘审实锤）：这个函数是全部武装点（失败 upgrade /
      // claim POST / 裸 GET / DELETE / fetch() 握手成功 / alarm() 收尾）共用
      // 的唯一 setAlarm 落点——未认领房上每个 426/401/畸形 claim 都会走到
      // 这里一次，之前无条件重写，同一个固定回收时刻被反复 setAlarm 成了白嫖
      // storage 写。武装前先读现有 alarm 比对：已经排着一个相同或更早的时刻，
      // 就没有必要再写一次——它到点照样会触发这个函数重新计算并正确重排（不
      // 是漏排，只是省掉这次冗余写）；只有算出的新 nearest 确实比现有更早（或
      // 现有压根没排）时才真正调用 setAlarm。不破坏 min 语义本身：上面的 min
      // 计算永远覆盖 token alarm 与回收 alarm 共用 slot 的全部候选类型，这里
      // 只是决定「要不要现在就把这个已经算对的 min 写进 storage」。
      const existingAlarm = typeof this.ctx.storage.getAlarm === "function"
        ? await this.ctx.storage.getAlarm()
        : null;
      if (existingAlarm == null || existingAlarm > nearest) {
        await this.ctx.storage.setAlarm(nearest);
      }
    }
  }

  canDeliverOutbound(ws, payload, now = Date.now()) {
    const attachment = safeAttachment(ws);
    if (attachment.subject_limit_closed === true) return false;
    if (attachment.role === "desktop" && attachment.scope === "desktop") {
      return attachment.registry_ready === true &&
        Number(attachment.epoch) === store.getCurrentEpoch(this.sql);
    }
    if (!attachment.scope) return false;

    const frameType = typeof payload?.t === "string" ? payload.t : payload?.kind;
    const isPairingFrame = typeof frameType === "string" && frameType.startsWith("pair.");
    const isRefreshForward = frameType === "token.refresh.forward";
    const isRefreshReceipt = ["token.refresh.ok", "token.refresh.fail"].includes(frameType);

    // S1ja F2：legacy remote 的「视同活 current remote」豁免已撤（同族于
    // authorizeInboundSocket 那条，同一批一并收紧）——没有 subject 就没有
    // token_subjects/token_aliases 行可查，不可能是真实的当前授权连接，
    // 不再投递任何出站帧给它。
    if (!attachment.subject) return false;
    if (!this.isOfficialAttachmentLive(attachment, now)) {
      this.closeSocketForReauthorization(ws);
      return false;
    }
    if (isPairingFrame) return attachment.scope === "pairing";
    if (isRefreshForward) return false;
    // S1i2 §9.6/P1-b：refresh 回执改走 deliverRefreshReceipt 自有谓词——本闸
    // 恒不投递这两个帧型，不是遗漏。旧实现在这里放行的条件是「发送目标 socket
    // 自己的 attachment.generation 仍等于 subject 当前 generation」，但桌面
    // 轮换升代后手机 socket 的 attachment 章还是旧代，isOfficialAttachmentLive
    // 已经在上面把它判死、直接 return false——回执因此永远送不到这条分支，
    // 每次轮换都被迫走「断线 + prev 重连 + journal 重放」的慢路径。
    // deliverRefreshReceipt 独立复核 token_subjects 的当前权威 generation
    // （不依赖目标 socket 自己的 attachment 是否还新鲜），是真正的投递闸。
    if (isRefreshReceipt) return false;
    return attachment.scope === "remote" && attachment.kind === "current";
  }

  closeSocketForReauthorization(ws) {
    try {
      ws.close(REAUTH_CLOSE_CODE, REAUTH_CLOSE_REASON);
    } catch {
      // close/alarm 可能与当前投递竞态；SQL 行状态仍是最终真相。
    } finally {
      // 连接就此消失，它攒着的聚合计数不能跟着丢——close 是三个 flush 时机之一
      // （另两个是攒满一批和 alarm）。close 本身抛错也不影响 flush。
      this.flushProtocolViolations();
    }
  }

  /**
   * 记一次协议违规：聚合计数先攒在内存里、攒满一批才落一次库；per-socket 计数
   * 走 WeakMap。返回 true 表示这条 socket 已到 PROTOCOL_VIOLATION_LIMIT，调用
   * 方应当在回完错误帧之后关掉它。
   */
  recordProtocolViolation(ws = null) {
    this.pendingProtocolViolations += 1;
    if (this.pendingProtocolViolations >= PROTOCOL_VIOLATION_LIMIT) this.flushProtocolViolations();
    if (!ws) return false;
    const count = Number(this.socketProtocolViolations.get(ws) || 0) + 1;
    this.socketProtocolViolations.set(ws, count);
    return count >= PROTOCOL_VIOLATION_LIMIT;
  }

  flushProtocolViolations() {
    if (this.pendingProtocolViolations === 0) return;
    const pending = this.pendingProtocolViolations;
    this.pendingProtocolViolations = 0;
    // 墓碑房的业务表已被 purge，聚合计数没有可写的去处——丢掉即可，房间已终结。
    if (!this.assertRoomLive()) return;
    const count = Number(store.getMeta(this.sql, "protocol_violation_count", "0"));
    store.setMeta(this.sql, "protocol_violation_count", count + pending);
  }

  /**
   * 房间级 IP 桶盐：首次活房初始化时随机生成 32 字节并落 room_state（生成与
   * 落库同一个事务内完成）。有盐之后 ip_bucket_key = SHA-256(salt || IP) 截断，
   * 同一 IP 在同一房间恒定命中同一个桶，但拿到 key 的人反推不出 IP——裸
   * sha256(ip) 的取值空间只有全部 IPv4 地址那么大，离线枚举就能还原。盐只留
   * 在 SQL 里，不进 attachment、不进日志。
   * SEC-1：盐从 room_meta（业务 schema，鉴权成功后才建）迁到 room_state（哨兵
   * 表，恒存在）——deriveIpBucketKey 在鉴权前（S1i2 §9.8）就要用它，若仍挂
   * 业务 schema，这一步会把业务表拽回鉴权前无条件建的老问题。
   */
  ensureIpBucketSalt() {
    return store.withTransaction(this.sql, () => {
      const existing = store.getRoomIpBucketSalt(this.sql);
      if (existing) return existing;
      const salt = bytesToHex(globalThis.crypto.getRandomValues(new Uint8Array(32)));
      store.setRoomIpBucketSalt(this.sql, salt);
      return salt;
    });
  }

  async deriveIpBucketKey(ip) {
    if (!this.ipBucketSalt) this.ipBucketSalt = this.ensureIpBucketSalt();
    const digest = await globalThis.crypto.subtle.digest(
      "SHA-256",
      concatBytes(hexToBytes(this.ipBucketSalt), new TextEncoder().encode(ip))
    );
    return bytesToHex(new Uint8Array(digest).slice(0, 16));
  }

  currentQuotaState() {
    const period = currentPeriod(Date.now());
    const count = store.getQuotaCount(this.sql, period);
    const limit = Number(this.env && this.env.MONTHLY_MILESTONE_LIMIT) || DEFAULT_MONTHLY_MILESTONE_LIMIT;
    return evaluateQuota({ count, limit });
  }

  assertAttachmentBudget(obj) {
    const bytes = new TextEncoder().encode(JSON.stringify(obj)).length;
    if (bytes > ATTACHMENT_BYTE_BUDGET) {
      throw new Error(`serializeAttachment payload ${bytes}B exceeds ${ATTACHMENT_BYTE_BUDGET}B budget`);
    }
  }
}

function safeAttachment(ws) {
  try {
    return ws.deserializeAttachment() || {};
  } catch {
    return {};
  }
}

// §9.6 wire-v1.json token_refresh_valid / token_refresh_request_id_missing 同源。
function requiredNonEmptyString(payload, field) {
  return typeof payload[field] === "string" && payload[field].length > 0 ? null : `${field}_required`;
}

// R2：request_id 落 refresh_requests PRIMARY KEY，128 字节口径同
// envelope.js:135-138 的 command_id 上限——按 UTF-8 字节计，不用 .length。
function requestIdTooLong(value) {
  return typeof value === "string" && new TextEncoder().encode(value).length > REQUEST_ID_MAX_BYTES;
}

function tokenRefreshShapeError(payload) {
  return requiredNonEmptyString(payload, "request_id") ??
    (requestIdTooLong(payload.request_id) ? "request_id_too_long" : null) ??
    requiredNonEmptyString(payload, "ct") ??
    requiredNonEmptyString(payload, "n");
}

// token_refresh_ok_valid / token_refresh_fail_valid / token_refresh_fail_in_flight_no_close_valid
// 同源；fail 帧结构上不带 generation（§9.6：close=true 仅用于连续 ≥3 次
// 无效判连续失败，缺省=良性重试不断连接）。
function tokenRefreshReceiptShapeError(payload) {
  const requestIdError = requiredNonEmptyString(payload, "request_id");
  if (requestIdError) return requestIdError;
  const subjectError = requiredNonEmptyString(payload, "subject");
  if (subjectError) return subjectError;

  if (payload.t === "token.refresh.ok") {
    if (!Number.isSafeInteger(payload.generation) || payload.generation <= 0) return "generation_required";
    return requiredNonEmptyString(payload, "ct") ?? requiredNonEmptyString(payload, "n");
  }
  if (payload.t === "token.refresh.fail") {
    const reasonError = requiredNonEmptyString(payload, "reason");
    if (reasonError) return reasonError;
    if (Object.hasOwn(payload, "close") && typeof payload.close !== "boolean") return "close_invalid";
    return null;
  }
  return "frame_type_invalid";
}

function tokenPutFrameToEntry(payload) {
  if (!payload.current || typeof payload.current !== "object" || Array.isArray(payload.current)) {
    throw new TypeError("current token alias required");
  }
  if (payload.subject === "pairing") {
    if (payload.scope !== "pairing") throw new TypeError("pairing subject requires pairing scope");
    if (payload.prev !== undefined) throw new TypeError("pairing subject forbids prev alias");
    if (payload.current.refresh_until !== undefined) {
      throw new TypeError("pairing subject forbids refresh_until");
    }
  }
  const aliases = [{
    token_hash: payload.current.token_hash,
    kind: "current",
    generation: payload.generation,
    access_expires: payload.current.access_expires,
    valid_until: payload.subject === "pairing"
      ? payload.current.access_expires
      : payload.current.refresh_until,
  }];
  if (payload.prev !== undefined) {
    if (!payload.prev || typeof payload.prev !== "object" || Array.isArray(payload.prev)) {
      throw new TypeError("invalid prev token alias");
    }
    if (payload.prev.token_hash === undefined) {
      throw new TypeError("prev token hash required");
    }
    aliases.push({
      token_hash: payload.prev.token_hash,
      kind: "prev",
      generation: payload.prev.generation,
      access_expires: null,
      valid_until: payload.prev.prev_expires,
    });
  }
  return {
    subject: payload.subject,
    generation: payload.generation,
    state: "active",
    scope: payload.scope,
    aliases,
  };
}

function tokenMutationRejectReason(error) {
  const message = error instanceof Error ? error.message : "";
  if (message.includes("already belongs")) return "token_hash_conflict";
  if (message.includes("pairing scope")) return "pairing_scope_required";
  if (message.includes("forbids prev") || message.includes("only supports a current")) return "pairing_prev_forbidden";
  if (message.includes("generation must be positive")) return "generation_must_be_positive";
  if (message.includes("token subject generation")) return "generation_invalid";
  if (message.includes("requires scope") || message.includes("device subject")) return "scope_invalid";
  if (message.includes("token subject")) return "subject_invalid";
  if (message.includes("token scope")) return "scope_invalid";
  if (message.includes("prev token hash required")) return "prev_token_hash_required";
  if (message.includes("token hash")) return "token_hash_invalid";
  if (message.includes("access_expires")) return "access_expires_after_refresh_until";
  if (message.includes("exceeds JSON safe integer")) return "timestamp_exceeds_json_safe_integer";
  if (message.includes("must be positive")) return "timestamp_must_be_positive";
  if (message.includes("expiry") || message.includes("timestamp") || message.includes("refresh_until")) return "timestamp_invalid";
  if (message.includes("close flag")) return "close_invalid";
  if (message.includes("current")) return "current_required";
  if (message.includes("prev")) return "prev_invalid";
  return null;
}

function bytesToHex(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function concatBytes(left, right) {
  const joined = new Uint8Array(left.length + right.length);
  joined.set(left, 0);
  joined.set(right, left.length);
  return joined;
}

// windowMs 可覆盖（G8 per-IP 消息粗桶复用本原语，窗口口径与 upgrade 失败桶
// 数值恰好一样但概念独立，仍显式传参不暗中共享常量）；不传时保持 upgrade
// 认证失败桶的既有默认行为不变。
function bucketAtLimit(buckets, key, limit, now, windowMs = UPGRADE_FAILURE_WINDOW_MS) {
  const bucket = buckets.get(key);
  if (!bucket || now >= bucket.startedAt + windowMs) return false;
  return bucket.attempts >= limit;
}

function recordBucketHit(buckets, key, now, windowMs = UPGRADE_FAILURE_WINDOW_MS) {
  const bucket = buckets.get(key);
  if (!bucket || now >= bucket.startedAt + windowMs) {
    buckets.set(key, { startedAt: now, attempts: 1 });
    return;
  }
  bucket.attempts += 1;
}

// G8 R2 附带风险（codex）：per-IP 消息粗桶现在对「这个 IP 上所有 remote
// 角色入站帧」计费（见 takeIpMessageSlot），覆盖面比旧版（只挂 input/
// control）大得多，一个长寿命 isolate 理论上会见到远更多不同的
// ip_bucket_key，Map 本身没有 TTL、只会单调增长。这不是精确 LRU，只是把
// 已经过期窗口（不会再影响限速判断，纯占内存）的条目摘掉——够防慢性膨胀，
// 调用方只在 Map 尺寸超过阈值时才扫一次，正常流量下不额外付出这个 O(n)。
function evictExpiredBuckets(buckets, now, windowMs) {
  for (const [key, bucket] of buckets) {
    if (now >= bucket.startedAt + windowMs) buckets.delete(key);
  }
}
