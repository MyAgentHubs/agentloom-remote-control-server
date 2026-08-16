import { readFileSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { RoomDO } from "../src/room-do.js";
import * as store from "../src/room-store.js";

// DP-1（data-plane-v1 fixture 层）：presence / input.ack / input.expired / replay.head 四类
// 明文帧的真路径消费方——驱动真实 RoomDO.webSocketMessage（不是手写校验器），断言 relay
// 实际下发/广播的帧与 `remote-relay/fixtures/data-plane-v1.json` 的样张逐字段对齐。
//
// 本文件的连接搭建方式照抄 test/room-do.test.js 的既有做法（该文件顶部注释解释了原因：
// RoomDO 依赖的 Cloudflare Hibernation API 本机跑不了，`connect()` 手工搭一个「握手已完成」
// 的等价状态，只顶掉运行时基础设施，业务逻辑一行不改）；本文件不从 room-do.test.js import
// 这些 helper（它们不是导出的模块函数），按这份仓库里每个 *.test.js 各自持有一份同款薄替身
// 的既有惯例（s1f1-fixture.test.js / room-lifecycle-fixture.test.js / g8-message-rate-limit.test.js
// 均如此）在本文件内重新搭一份最小子集。

const FIXTURE = JSON.parse(
  readFileSync(new URL("../fixtures/data-plane-v1.json", import.meta.url), "utf8")
);

function fixtureCase(name) {
  const found = FIXTURE.cases.find((item) => item.name === name);
  assert.ok(found, `data-plane-v1 fixture missing case ${name}`);
  return found;
}

const ROOM = "b".repeat(32);
const CT = Buffer.from("hello ciphertext").toString("base64");
const N12 = Buffer.alloc(12, 7).toString("base64"); // 12 字节 nonce

function makeStorageSql() {
  const db = new DatabaseSync(":memory:");
  return {
    exec(query, ...params) {
      const isSelect = /^\s*(SELECT|PRAGMA)/i.test(query);
      const stmt = db.prepare(query);
      if (isSelect) return stmt.all(...params);
      stmt.run(...params);
      return [];
    },
  };
}

function makeCtx(storageSql = makeStorageSql()) {
  const registry = [];
  return {
    storage: {
      sql: storageSql,
      transactionSync(callback) {
        return callback();
      },
    },
    acceptWebSocket(ws, tags = []) {
      registry.push({ ws, tags });
    },
    getWebSockets(tag) {
      if (!tag) return registry.map((r) => r.ws);
      return registry.filter((r) => r.tags.includes(tag)).map((r) => r.ws);
    },
  };
}

function makeFakeWs() {
  let attachment = null;
  const sent = [];
  return {
    sent,
    send(text) {
      sent.push(typeof text === "string" ? JSON.parse(text) : text);
    },
    close() {},
    serializeAttachment(obj) {
      attachment = obj;
    },
    deserializeAttachment() {
      return attachment;
    },
  };
}

function makeRoom(env = {}) {
  const ctx = makeCtx();
  const room = new RoomDO(ctx, env);
  store.ensureBusinessSchema(room.sql);
  return { room, ctx };
}

// 同 test/room-do.test.js 的 connect()：手工搭一条「握手已完成」的连接，remote 分支落一行
// 真实 registry-backed subject（S1ja F2 后 legacy 无 subject 豁免已撤，canDeliverOutbound/
// authorizeInboundSocket 都 fail-closed，没有这行 attachment 会被判定连接不合法）。
let autoConnectionIdCounter = 0;

function connect(room, ctx, role, { connectionId, now = Date.now(), registryReady = true } = {}) {
  const ws = makeFakeWs();
  const epoch = role === "desktop" ? store.bumpEpoch(room.sql) : store.getCurrentEpoch(room.sql);
  ctx.acceptWebSocket(ws, [role]);
  const autoId = ++autoConnectionIdCounter;
  const attachment = {
    epoch,
    role,
    scope: role === "desktop" ? "desktop" : "remote",
    lastSeq: 0,
    connectedAt: now,
    connection_id: connectionId ?? `dp1-auto-conn-${autoId}`,
    // registryReady:false 留给 replay.head 测试——需要一条尚未过 token.sync 激活
    // 屏障的桌面连接，驱动真实 webSocketMessage(token.sync) 触发 desktopHello
    // （room-do.js:1160-1165），而不是直接调 room.desktopHello 绕过这道闸。
    ...(role === "desktop"
      ? registryReady
        ? { registry_ready: true }
        : { registry_ready: false, registry_sync_deadline: now + 30_000 }
      : {}),
  };
  if (role === "remote") {
    const subject = `device:11111111-1111-4111-8111-${String(autoId).padStart(12, "0")}`;
    store.putTokenRegistryEntry(room.sql, {
      subject,
      generation: 1,
      state: "active",
      scope: "remote",
      aliases: [{
        token_hash: String(autoId).padStart(64, "0"),
        kind: "current",
        generation: 1,
        access_expires: now + 60_000,
        valid_until: now + 120_000,
      }],
    }, now);
    Object.assign(attachment, {
      subject,
      kind: "current",
      generation: 1,
      alias_generation: 1,
      access_expires: now + 60_000,
      valid_until: now + 120_000,
    });
  }
  ws.serializeAttachment(attachment);
  return ws;
}

function envelope(overrides = {}) {
  const kind = overrides.kind ?? "event";
  return {
    v: 1,
    room: ROOM,
    epoch: 1,
    kind,
    session: "s1",
    command_id: null,
    seq: null,
    client_msg_id: kind === "event" ? "cmid-dp1-default" : null,
    ct: CT,
    n: N12,
    ts: Date.now(),
    ...overrides,
  };
}

async function send(room, ws, payload) {
  await room.webSocketMessage(ws, JSON.stringify(payload));
}

function lastSent(ws) {
  return ws.sent[ws.sent.length - 1];
}

// ============================================================================
// presence
// ============================================================================

test("relay presence 明文帧经 webSocketMessage 原样广播给其它在线连接", async () => {
  const { room, ctx } = makeRoom();
  const sender = connect(room, ctx, "remote");
  const observer = connect(room, ctx, "remote");
  const frame = fixtureCase("presence_broadcast").frame;

  await send(room, sender, frame);

  assert.deepEqual(lastSent(observer), frame);
  assert.equal(sender.sent.length, 0, "broadcastRaw 的 excludeWs 排除发送方自己");
});

// ============================================================================
// input.ack
// ============================================================================

test("relay input.ack 合法确认经 webSocketMessage 删除 pending_input 行并广播回执", async () => {
  const { room, ctx } = makeRoom();
  const remoteWs = connect(room, ctx, "remote");
  const ackFrame = fixtureCase("input_ack_valid_deletes_pending").frame;

  // 桌面此刻不在线（房间 epoch 仍是初始值 0）——input 先暂存进 pending_input。
  await send(room, remoteWs, envelope({
    kind: "input", command_id: ackFrame.command_id, seq: null, epoch: 0,
  }));
  assert.equal(
    store.drainDeliverableInput(room.sql, Date.now()).deliverable.length,
    1,
    "前置：桌面离线，input 应先暂存进 pending_input"
  );

  const desktopWs = connect(room, ctx, "desktop");
  await send(room, desktopWs, ackFrame);

  assert.equal(
    store.drainDeliverableInput(room.sql, Date.now()).deliverable.length,
    0,
    "桌面确认后 pending_input 对应行必须被删除"
  );
  assert.deepEqual(lastSent(remoteWs), ackFrame);
});

test("relay input.ack 缺 command_id 经 webSocketMessage 不删除 pending_input 行且不崩溃", async () => {
  const { room, ctx } = makeRoom();
  const remoteWs = connect(room, ctx, "remote");
  const badAck = fixtureCase("input_ack_missing_command_id_no_delete").frame;
  assert.equal(typeof badAck.command_id, "undefined", "样张必须真的缺这个字段");

  await send(room, remoteWs, envelope({
    kind: "input", command_id: "cmd-dp1-untouched", seq: null, epoch: 0,
  }));
  assert.equal(store.drainDeliverableInput(room.sql, Date.now()).deliverable.length, 1);

  const desktopWs = connect(room, ctx, "desktop");
  await assert.doesNotReject(() => send(room, desktopWs, badAck));

  assert.equal(
    store.drainDeliverableInput(room.sql, Date.now()).deliverable.length,
    1,
    "缺 command_id 的 ack 不应删除任何 pending_input 行"
  );
  // 完整外显行为（room-do.js:745-757）：command_id 缺失只影响删不删 pending_input 行，
  // 不影响是否转发——handlePlainFrame 的 input.ack 分支无条件 broadcastToRemotes(payload)，
  // 缺字段的坏 ack 仍会原样广播给房间内远端，逐字段对样张。
  assert.deepEqual(
    lastSent(remoteWs),
    badAck,
    "缺 command_id 的坏 ack 仍应原样广播给远端，不是静默吞掉"
  );
});

// ============================================================================
// input.expired
// ============================================================================

test("relay 过期 pending_input 行经 webSocketMessage 触发清扫并广播 input.expired", async () => {
  const { room, ctx } = makeRoom();
  const remoteWs = connect(room, ctx, "remote"); // 桌面不上线，走 purgeExpiredPendingInput 分支
  const expiredFrame = fixtureCase("input_expired_broadcast").frame;
  const longAgo = Date.now() - 1_000_000;
  store.enqueueInput(room.sql, {
    commandId: expiredFrame.command_id,
    session: "s1",
    envelopeJson: JSON.stringify({ seed: 0 }),
    now: longAgo,
    ttlMs: 1, // expires_at = longAgo + 1，早就过期
  });
  assert.equal(store.pendingInputStats(room.sql).rowCount, 1, "前置：种下一条已过期行");

  await send(room, remoteWs, envelope({
    kind: "input", command_id: "cmd-dp1-after-purge", seq: null, epoch: 0,
  }));

  const expiredFrames = remoteWs.sent.filter((frame) => frame.t === "input.expired");
  assert.equal(expiredFrames.length, 1);
  assert.deepEqual(expiredFrames[0], expiredFrame);
  assert.equal(
    store.pendingInputStats(room.sql).rowCount,
    1,
    "过期行清空后应只剩这条新入队的（不是它本身，是它触发清扫）"
  );
});

// ============================================================================
// replay.head
// ============================================================================

test("relay desktopHello 在 registry_ready 激活后下发的首帧 replay.head 与 store 现状一致", async () => {
  const { room, ctx } = makeRoom();
  // registryReady:false——不直接调 room.desktopHello，而是经真实 webSocketMessage(token.sync)
  // 驱动 registry_ready false->true 的激活屏障（room-do.js:1160-1165），desktopHello 只应
  // 在 token.sync.ack 之后才被真正触发。
  const desktopWs = connect(room, ctx, "desktop", {
    connectionId: "dp1-replay-head-desktop",
    registryReady: false,
  });
  const epoch = store.getCurrentEpoch(room.sql); // connect() 里已 bumpEpoch 一次 -> 1
  store.insertMilestone(room.sql, { epoch, session: "s1", kind: "event", ct: CT, n: N12, ts: 1 });
  store.insertMilestone(room.sql, { epoch, session: "s1", kind: "event", ct: CT, n: N12, ts: 2 });

  assert.equal(
    room.onlineDesktop(),
    null,
    "前置：token.sync 前 registry_ready 未激活，不应被选中为在线桌面"
  );

  await send(room, desktopWs, { t: "token.sync", revision: 1, entries: [] });

  assert.equal(
    room.onlineDesktop(),
    desktopWs,
    "token.sync.ack 后 registry_ready 必须真的翻转，desktop 才算在线"
  );
  assert.deepEqual(
    desktopWs.sent.map((frame) => frame.t),
    ["token.sync.ack", "replay.head"],
    "真实激活链：token.sync.ack 之后紧跟 desktopHello 下发的 replay.head 首帧"
  );
  assert.deepEqual(desktopWs.sent[1], fixtureCase("replay_head_on_connect").frame);
});
