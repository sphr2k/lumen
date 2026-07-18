# Lumen Verified Launch

Lumen verifies a static artifact bundle before executing browser-delivered
client bytes. A Lumen Link pins the bundle index digest; the bundle may then
embed its own notaries, release manifest, runtime configuration, and assets.

```text
Lumen Link -> index.json digest check -> embedded notary signature -> target hashes -> launch
```

IPFS, gateways, tunnels, and mirrors are delivery mechanisms only. They do not
become trust anchors.

## Scripts

```bash
bun install
bun run test
bun run build
bun run validate
```

## Links

Production links use a compact versioned launch payload:

```text
https://launcher.example/#l=v1.<base64url-json>
```

Readable debug links remain supported for diagnostics:

```text
https://launcher.example/#cid=bafy...&digest=sha256:...&release=releases/app/manifest.json&runtime=runtime/app.json
```

The expanded legacy names `source`, `ipfs`, `bundleDigest`, `releasePath`, and
`runtimePath` are also accepted.

## CLI

```bash
bun run bin/lumen.ts verify 'https://launcher.example/#source=https://gateway.example/ipfs/bafy.../&bundleDigest=sha256:...'
```
