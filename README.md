# AgentLoom Remote Control Server

An end-to-end-encrypted relay that lets you drive the coding agents running in
your desktop [AgentLoom](https://myagenthubs.com) from your phone — scan a QR
code, watch the session stream live, send input, approve or stop a run.

The relay is a **Cloudflare Workers + Durable Objects** service. It only ever
sees ciphertext: it routes encrypted envelopes between your desktop and your
phone and never holds any content key. This repository is the relay you can
**self-host on your own Cloudflare account**, plus a prebuilt copy of the mobile
web client so a fresh deploy is usable with zero extra build steps.

## What it does

- **One Durable Object per room.** A room is the meeting point between one
  desktop and its paired remote devices. Milestone events are stored in the
  DO's SQLite; live frames are forwarded and never persisted.
- **Token-gated admission.** Every connection must present a capability token
  the desktop issued during pairing. No token, unknown room, or wrong token →
  `401`. There is no anonymous "just have a look" path.
- **Default-deny routing.** The relay enforces direction (a remote can't forge
  an agent milestone; a desktop can't inject remote input) purely on the
  metadata it can read — it can't read the content.

## Security model — the honest boundaries

This matters, so it's stated plainly rather than sold.

- ✅ **End-to-end encrypted.** The relay forwards ciphertext only. Content keys
  (`K_room`, `K_pair`) live on the desktop and the paired devices, never on the
  relay. If the relay is compromised, the attacker still can't read your
  sessions.
- ⚠️ **Metadata is not encrypted.** The relay can see room IDs, session IDs,
  message sequence numbers, frame types, timing, sizes, token hashes, and how
  many devices are connected. It cannot see message content. Do not describe
  this as "zero knowledge."
- ⚠️ **Same-origin web hosting is a trust assumption.** When the relay also
  serves the mobile web client (the `web-dist/` bundle) on its own origin, the
  decryption JavaScript is delivered by whoever runs the relay. E2EE protects
  you from outside attackers, **not** from a relay operator who swaps in a
  key-stealing frontend. If you self-host, you are that operator for your own
  deploy.
- ⚠️ **Pairing code = full credential, for 300 seconds.** The `#p=` fragment in
  the pairing URL is single-use and expires after 5 minutes. Inside that window
  it is the whole credential — anyone who sees the QR code or pairing string and
  uses it first pairs as a legitimate device. There is no second factor. Don't
  let the QR code be screenshotted, shared, or shoulder-surfed while pairing.

## Deploy it yourself

Prerequisites: a Cloudflare account and [`wrangler`](https://developers.cloudflare.com/workers/wrangler/).

1. Clone this repo.
2. Edit `wrangler.toml`:
   - Change `name` to your own worker name.
   - Either keep `workers_dev = true` (you'll get `<name>.<your-subdomain>.workers.dev`),
     or set your own custom domain under `[[routes]]` (replace the
     `your-relay.example.com` placeholder) if the zone is on the same Cloudflare
     account.
3. Deploy:
   ```bash
   npx wrangler deploy
   ```

The `[assets]` binding serves the prebuilt mobile web client from `web-dist/`,
so a deployed relay is immediately usable — point your desktop AgentLoom's
remote-control setting at your relay URL, generate a QR code, and scan it.

## Local development

```bash
npm install
npm test                 # pure-logic unit tests (node:test + node:sqlite)
npx wrangler dev         # local Durable Object environment
```

The tests don't need Cloudflare — `src/room-store.js`'s SQL runs against Node's
built-in `node:sqlite`, exercising the *same* code the real DO runs, not a
look-alike reimplementation.

## Repository layout

```
src/            relay source (auth · room DO · store · quota · envelope · security headers · router)
test/           node:test suites
fixtures/       protocol contract samples (wire / data-plane / KDF / msg-id derivation)
web-dist/       prebuilt mobile web client (static assets served same-origin)
wrangler.toml   Cloudflare Workers config
```

## About the web client

`web-dist/` is a **prebuilt** copy of the mobile web client. Its source is part
of the AgentLoom product and is not included here; this repo ships the built
artifact so self-hosters get the same "scan and go" experience without building
a frontend. To upgrade it, drop a newer build into `web-dist/`.

## License

The relay source in this repository is licensed under **AGPL-3.0-only** — see
[`LICENSE`](./LICENSE). AGPL's network-copyleft means anyone who runs a modified
version of this relay as a network service must make their modified source
available.

The prebuilt mobile web client under `web-dist/` is a build artifact of the
AgentLoom product, © MyAgentHubs, shipped here so a fresh deploy works
out of the box. It is provided for deploying this relay; its source is not part
of this repository and is not covered by the AGPL grant above.
