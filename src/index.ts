export type LumenVerificationResult = Readonly<{
  source: string;
  generation: number;
  release: LumenStaticWebRelease;
  runtimeBytes?: Uint8Array;
  assets: ReadonlyMap<string, Uint8Array>;
}>;

export type LumenProgressEvent = Readonly<{
  state: "fetching" | "verified" | "failed";
  path: string;
  source: string;
  url: string;
  elapsedMs?: number;
  message?: string;
}>;

export type LumenVerifyInput = Readonly<{
  source: string;
  bundleDigest: string;
  releasePath?: string;
  runtimePath?: string;
  fetchTimeoutMs?: number;
  fetch?: typeof fetch;
  requireLaunchSource?: boolean;
  onProgress?: (event: LumenProgressEvent) => void;
}>;

export class LumenError extends Error {
  constructor(
    readonly code:
      | "BAD_INPUT"
      | "FETCH_FAILED"
      | "DIGEST_MISMATCH"
      | "INVALID_INDEX"
      | "INVALID_SIGNATURE"
      | "INVALID_TARGET"
      | "INVALID_RELEASE"
      | "LAUNCH_UNAVAILABLE",
    message: string
  ) {
    super(message);
    this.name = "LumenError";
  }
}

type LumenIndexEnvelope = Readonly<{
  signed: LumenIndexSigned;
  signatures: readonly LumenSignature[];
}>;

type LumenIndexSigned = Readonly<{
  schema: "lumen/index/1";
  generation: number;
  createdAt: string;
  expiresAt: string;
  notaries: readonly LumenNotary[];
  targets: Record<string, LumenTarget>;
}>;

type LumenNotary = Readonly<{
  id: string;
  algorithm: "ECDSA-P256-SHA256";
  publicKeySpkiBase64: string;
  publicKeySpkiSha256: string;
}>;

type LumenSignature = Readonly<{
  notaryId: string;
  signatureBase64: string;
}>;

type LumenTarget = Readonly<{
  sha256: string;
  length: number;
  mediaType?: string;
  schema?: string;
}>;

type LumenStaticWebRelease = Readonly<{
  schema: "lumen/static-web-release/1";
  version: string;
  entrypoint: string;
  assets: Record<string, LumenTarget>;
}>;

type LumenLaunchPayload = Readonly<{
  v: 1;
  s?: string;
  c?: string;
  d: string;
  r?: string;
  u?: string;
}>;

const textDecoder = new TextDecoder();
const textEncoder = new TextEncoder();

export async function verifyLumenBundle(input: LumenVerifyInput): Promise<LumenVerificationResult> {
  const request = input.fetch ?? fetch;
  return await verifyLumenBundleFromSources({ ...input, sources: sourceCandidates(input.source), fetch: request });
}

async function verifyLumenBundleFromSources(input: LumenVerifyInput & { sources: readonly string[]; fetch: typeof fetch }): Promise<LumenVerificationResult> {
  const request = input.fetch;
  const sources = input.sources.map(ensureTrailingSlash);
  const timeoutMs = input.fetchTimeoutMs;
  const indexBytes = await fetchVerifiedBundlePath(request, sources, "index.json", timeoutMs, input.onProgress, async (bytes) => {
    await assertSha256Digest(bytes, input.bundleDigest, "index.json");
  });

  const index = parseIndex(indexBytes);
  await verifyIndexSignature(index);

  const releaseTargetPath = input.releasePath ?? selectOnlyTarget(index.signed.targets, "lumen/static-web-release/1");
  const releaseBytes = await fetchTarget(request, sources, index.signed.targets, releaseTargetPath, timeoutMs);
  const release = parseRelease(releaseBytes);

  const runtimeBytes = input.runtimePath === undefined
    ? undefined
    : await fetchTarget(request, sources, index.signed.targets, input.runtimePath, timeoutMs);

  const assets = new Map<string, Uint8Array>();
  for (const [path, target] of Object.entries(release.assets)) {
    assertSafeRelativePath(path);
    const bytes = await fetchVerifiedBundlePath(request, sources, path, timeoutMs, input.onProgress, async (bytes) => {
      await assertTargetBytes(bytes, target, path);
    });
    assets.set(path, bytes);
  }

  const launchSource = input.requireLaunchSource === true
    ? await selectLaunchSource(request, sources, release.assets, timeoutMs, input.onProgress)
    : undefined;

  return {
    source: launchSource ?? sources[0] ?? ensureTrailingSlash(input.source),
    generation: index.signed.generation,
    release,
    ...(runtimeBytes === undefined ? {} : { runtimeBytes }),
    assets
  };
}

export function parseLumenLaunchUrl(url: string): LumenVerifyInput {
  const parsed = new URL(url);
  const params = new URLSearchParams(parsed.hash.startsWith("#") ? parsed.hash.slice(1) : parsed.hash);
  const packed = params.get("l");
  if (packed !== null) return unpackLaunchPayload(packed);

  const bundleDigest = params.get("digest") ?? params.get("bundleDigest");
  if (bundleDigest === null) throw new LumenError("BAD_INPUT", "Launch URL is missing digest");

  const source = params.get("source");
  const ipfs = params.get("cid") ?? params.get("ipfs");
  const resolvedSource = source ?? (ipfs === null ? undefined : `https://dweb.link/ipfs/${ipfs}/`);
  if (resolvedSource === undefined) throw new LumenError("BAD_INPUT", "Launch URL is missing source or cid");

  const releasePath = optionalParam(params, "release") ?? optionalParam(params, "releasePath");
  const runtimePath = optionalParam(params, "runtime") ?? optionalParam(params, "runtimePath");
  return {
    source: resolvedSource,
    bundleDigest,
    ...(releasePath === undefined ? {} : { releasePath }),
    ...(runtimePath === undefined ? {} : { runtimePath })
  };
}

export function buildLumenLaunchUrl(input: {
  launcherUrl: string;
  source?: string;
  ipfs?: string;
  bundleDigest: string;
  releasePath?: string;
  runtimePath?: string;
  format?: "compact" | "debug";
}): string {
  const url = new URL(input.launcherUrl);
  const params = new URLSearchParams();
  if (input.format === "debug") {
    if (input.source !== undefined) params.set("source", input.source);
    if (input.ipfs !== undefined) params.set("cid", input.ipfs);
    params.set("digest", input.bundleDigest);
    if (input.releasePath !== undefined) params.set("release", input.releasePath);
    if (input.runtimePath !== undefined) params.set("runtime", input.runtimePath);
  } else {
    params.set("l", packLaunchPayload({
      v: 1,
      ...(input.source === undefined ? {} : { s: input.source }),
      ...(input.ipfs === undefined ? {} : { c: input.ipfs }),
      d: input.bundleDigest,
      ...(input.releasePath === undefined ? {} : { r: input.releasePath }),
      ...(input.runtimePath === undefined ? {} : { u: input.runtimePath })
    }));
  }
  url.hash = params.toString();
  return url.toString();
}

export function buildLumenLaunchAssetUrl(source: string, path: string): string {
  assertSafeRelativePath(path);
  const baseSource = ensureTrailingSlash(source);
  let parsed: URL;
  try {
    parsed = new URL(baseSource);
  } catch {
    return new URL(path, baseSource).toString();
  }

  const pathGatewayMatch = /^\/ipfs\/([^/]+)\/?$/u.exec(parsed.pathname);
  if (parsed.hostname === "dweb.link" && pathGatewayMatch !== null) {
    return new URL(path, `https://${pathGatewayMatch[1]}.ipfs.dweb.link/`).toString();
  }

  const inBrowserMatch = /^(.+)\.ipfs\.inbrowser\.link$/u.exec(parsed.hostname);
  if (inBrowserMatch !== null) {
    return new URL(path, `https://${inBrowserMatch[1]}.ipfs.dweb.link/`).toString();
  }

  return new URL(path, baseSource).toString();
}

function optionalParam(params: URLSearchParams, name: string): string | undefined {
  const value = params.get(name);
  return value === null || value === "" ? undefined : value;
}

function packLaunchPayload(payload: LumenLaunchPayload): string {
  return `v1.${bytesToBase64Url(textEncoder.encode(canonicalJson(payload)))}`;
}

function unpackLaunchPayload(value: string): LumenVerifyInput {
  if (!value.startsWith("v1.")) throw new LumenError("BAD_INPUT", "Unsupported Lumen launch payload version");
  let decoded: unknown;
  try {
    decoded = JSON.parse(textDecoder.decode(base64UrlToBytes(value.slice(3)))) as unknown;
  } catch {
    throw new LumenError("BAD_INPUT", "Lumen launch payload is not valid base64url JSON");
  }
  if (!isRecord(decoded) || decoded.v !== 1 || typeof decoded.d !== "string") {
    throw new LumenError("BAD_INPUT", "Lumen launch payload is invalid");
  }
  const source = typeof decoded.s === "string" ? decoded.s : undefined;
  const cid = typeof decoded.c === "string" ? decoded.c : undefined;
  const resolvedSource = source ?? (cid === undefined ? undefined : `https://dweb.link/ipfs/${cid}/`);
  if (resolvedSource === undefined) throw new LumenError("BAD_INPUT", "Lumen launch payload is missing source or cid");
  const releasePath = typeof decoded.r === "string" && decoded.r !== "" ? decoded.r : undefined;
  const runtimePath = typeof decoded.u === "string" && decoded.u !== "" ? decoded.u : undefined;
  return {
    source: resolvedSource,
    bundleDigest: decoded.d,
    ...(releasePath === undefined ? {} : { releasePath }),
    ...(runtimePath === undefined ? {} : { runtimePath })
  };
}

function sourceCandidates(source: string): string[] {
  const primary = ensureTrailingSlash(source);
  let url: URL;
  try {
    url = new URL(primary);
  } catch {
    return [primary];
  }
  const match = /^\/ipfs\/([^/]+)\/?$/u.exec(url.pathname);
  if (match === null) return [primary];
  const cid = match[1]!;
  return unique([
    primary,
    `https://dweb.link/ipfs/${cid}/`,
    `https://${cid}.ipfs.dweb.link/`,
    `https://ipfs.io/ipfs/${cid}/`,
    `https://gateway.pinata.cloud/ipfs/${cid}/`,
    `https://w3s.link/ipfs/${cid}/`
  ]);
}

function unique(values: readonly string[]): string[] {
  return [...new Set(values)];
}

function parseIndex(bytes: Uint8Array): LumenIndexEnvelope {
  const value = parseJson(bytes, "INVALID_INDEX", "index.json is not valid JSON");
  if (!isRecord(value) || !isRecord(value.signed) || !Array.isArray(value.signatures)) {
    throw new LumenError("INVALID_INDEX", "index.json must contain signed and signatures");
  }
  const signed = value.signed;
  if (signed.schema !== "lumen/index/1" || typeof signed.generation !== "number" || !Array.isArray(signed.notaries) || !isRecord(signed.targets)) {
    throw new LumenError("INVALID_INDEX", "index signed object is invalid");
  }
  return value as LumenIndexEnvelope;
}

function parseRelease(bytes: Uint8Array): LumenStaticWebRelease {
  const value = parseJson(bytes, "INVALID_RELEASE", "release manifest is not valid JSON");
  if (!isRecord(value) || value.schema !== "lumen/static-web-release/1" || typeof value.version !== "string" || typeof value.entrypoint !== "string" || !isRecord(value.assets)) {
    throw new LumenError("INVALID_RELEASE", "release manifest is invalid");
  }
  for (const [path, target] of Object.entries(value.assets)) {
    assertSafeRelativePath(path);
    assertTargetShape(target, path);
  }
  return value as LumenStaticWebRelease;
}

function parseJson(bytes: Uint8Array, code: LumenError["code"], message: string): unknown {
  try {
    return JSON.parse(textDecoder.decode(bytes)) as unknown;
  } catch {
    throw new LumenError(code, message);
  }
}

async function verifyIndexSignature(index: LumenIndexEnvelope): Promise<void> {
  const payload = textEncoder.encode(canonicalJson(index.signed));
  for (const signature of index.signatures) {
    const notary = index.signed.notaries.find((candidate) => candidate.id === signature.notaryId);
    if (notary === undefined) continue;
    const publicKeyBytes = base64ToBytes(notary.publicKeySpkiBase64);
    if (await sha256Hex(publicKeyBytes) !== notary.publicKeySpkiSha256) {
      throw new LumenError("INVALID_SIGNATURE", `Notary ${notary.id} public key fingerprint does not match`);
    }
    const publicKey = await crypto.subtle.importKey("spki", toArrayBuffer(publicKeyBytes), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      toArrayBuffer(derEcdsaSignatureToRaw(base64ToBytes(signature.signatureBase64))),
      toArrayBuffer(payload)
    );
    if (ok) return;
  }
  throw new LumenError("INVALID_SIGNATURE", "No valid Lumen Index signature found");
}

async function fetchTarget(request: typeof fetch, sources: readonly string[], targets: Record<string, LumenTarget>, path: string, timeoutMs: number | undefined): Promise<Uint8Array> {
  assertSafeRelativePath(path);
  const target = targets[path];
  if (target === undefined) throw new LumenError("INVALID_TARGET", `Target is not signed by index: ${path}`);
  assertTargetShape(target, path);
  const bytes = await fetchVerifiedBundlePath(request, sources, `targets/${path}`, timeoutMs, undefined, async (bytes) => {
    await assertTargetBytes(bytes, target, path);
  });
  return bytes;
}

async function fetchVerifiedBundlePath(
  request: typeof fetch,
  sources: readonly string[],
  path: string,
  timeoutMs: number | undefined,
  onProgress: ((event: LumenProgressEvent) => void) | undefined,
  verifyBytes: (bytes: Uint8Array) => Promise<void>
): Promise<Uint8Array> {
  const failures: string[] = [];
  const errors: unknown[] = [];
  return await new Promise((resolve, reject) => {
    let pending = sources.length;
    let settled = false;
    for (const source of sources) {
      const url = new URL(path, source).toString();
      void (async () => {
        const started = performanceNow();
        onProgress?.({ state: "fetching", path, source, url });
        try {
          const bytes = await fetchBytes(request, url, timeoutMs);
          if (settled) return;
          await verifyBytes(bytes);
          if (settled) return;
          onProgress?.({ state: "verified", path, source, url, elapsedMs: Math.round(performanceNow() - started) });
          settled = true;
          resolve(bytes);
        } catch (error) {
          if (settled) return;
          onProgress?.({ state: "failed", path, source, url, elapsedMs: Math.round(performanceNow() - started), message: messageOf(error) });
          errors.push(error);
          failures.push(`${url}: ${messageOf(error)}`);
          pending -= 1;
          if (pending === 0 && !settled) {
            if (errors.length === 1 && errors[0] instanceof LumenError && errors[0].code !== "FETCH_FAILED") {
              reject(errors[0]);
              return;
            }
            reject(new LumenError("FETCH_FAILED", `All repository sources failed for ${path}: ${failures.join(" | ")}`));
          }
        }
      })();
    }
  });
}

async function selectLaunchSource(
  request: typeof fetch,
  sources: readonly string[],
  assets: Record<string, LumenTarget>,
  timeoutMs: number | undefined,
  onProgress: ((event: LumenProgressEvent) => void) | undefined
): Promise<string> {
  const failures: string[] = [];
  for (const source of sources) {
    const checked = await Promise.all(Object.entries(assets).map(async ([path, target]) => {
      const url = new URL(path, source).toString();
      const started = performanceNow();
      onProgress?.({ state: "fetching", path: `launch:${path}`, source, url });
      try {
        const bytes = await fetchBytes(request, url, timeoutMs);
        await assertTargetBytes(bytes, target, path);
        onProgress?.({ state: "verified", path: `launch:${path}`, source, url, elapsedMs: Math.round(performanceNow() - started) });
        return true;
      } catch (error) {
        const message = messageOf(error);
        failures.push(`${url}: ${message}`);
        onProgress?.({ state: "failed", path: `launch:${path}`, source, url, elapsedMs: Math.round(performanceNow() - started), message });
        return false;
      }
    }));
    if (checked.every(Boolean)) return source;
  }
  throw new LumenError("LAUNCH_UNAVAILABLE", `Verified bundle bytes, but no single gateway can serve every launch asset: ${failures.join(" | ")}`);
}

async function fetchBytes(request: typeof fetch, url: string, timeoutMs = 15_000): Promise<Uint8Array> {
  let response: Response;
  const controller = new AbortController();
  let timeout: ReturnType<typeof setTimeout> | undefined;
  let timedOut = false;
  const timeoutPromise = new Promise<never>((_resolve, reject) => {
    timeout = setTimeout(() => {
      timedOut = true;
      controller.abort();
      reject(new LumenError("FETCH_FAILED", `Fetch timed out for ${url} after ${timeoutMs}ms`));
    }, timeoutMs);
  });
  try {
    response = await Promise.race([request(url, { signal: controller.signal }), timeoutPromise]);
  } catch (error) {
    if (timedOut) throw new LumenError("FETCH_FAILED", `Fetch timed out for ${url} after ${timeoutMs}ms`);
    throw new LumenError("FETCH_FAILED", `Fetch failed for ${url}: ${messageOf(error)}`);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
  if (!response.ok) throw new LumenError("FETCH_FAILED", `Fetch failed for ${url}: ${response.status}`);
  return new Uint8Array(await response.arrayBuffer());
}

function selectOnlyTarget(targets: Record<string, LumenTarget>, schema: string): string {
  const matches = Object.entries(targets).filter(([, target]) => target.schema === schema);
  if (matches.length !== 1) throw new LumenError("INVALID_TARGET", `Expected exactly one target with schema ${schema}`);
  return matches[0]![0];
}

function assertTargetShape(value: unknown, path: string): asserts value is LumenTarget {
  if (!isRecord(value) || typeof value.sha256 !== "string" || typeof value.length !== "number" || !Number.isSafeInteger(value.length) || value.length < 0) {
    throw new LumenError("INVALID_TARGET", `Target metadata is invalid for ${path}`);
  }
}

async function assertTargetBytes(bytes: Uint8Array, target: LumenTarget, label: string): Promise<void> {
  if (bytes.byteLength !== target.length) {
    throw new LumenError("DIGEST_MISMATCH", `${label} length mismatch`);
  }
  if (await sha256Hex(bytes) !== target.sha256) {
    throw new LumenError("DIGEST_MISMATCH", `${label} sha256 mismatch`);
  }
}

async function assertSha256Digest(bytes: Uint8Array, digest: string, label: string): Promise<void> {
  const match = /^sha256:([0-9a-f]{64})$/u.exec(digest);
  if (match === null) throw new LumenError("BAD_INPUT", `${label} digest must be sha256:<hex>`);
  if (await sha256Hex(bytes) !== match[1]) throw new LumenError("DIGEST_MISMATCH", `${label} sha256 mismatch`);
}

function assertSafeRelativePath(path: string): void {
  if (path === "" || path.startsWith("/") || path.includes("..") || path.includes("\\") || /^https?:/iu.test(path)) {
    throw new LumenError("INVALID_TARGET", `Unsafe bundle path: ${path}`);
  }
}

function ensureTrailingSlash(value: string): string {
  return value.endsWith("/") ? value : `${value}/`;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", toArrayBuffer(bytes));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value as Record<string, unknown>).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`).join(",")}}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function performanceNow(): number {
  return typeof performance === "undefined" ? Date.now() : performance.now();
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64UrlToBytes(value: string): Uint8Array {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return base64ToBytes(padded);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function derEcdsaSignatureToRaw(signature: Uint8Array): Uint8Array {
  if (signature[0] !== 0x30) throw new LumenError("INVALID_SIGNATURE", "ECDSA signature is not DER encoded");
  let offset = 2;
  if (signature[1] === 0x81) offset = 3;
  if (signature[offset] !== 0x02) throw new LumenError("INVALID_SIGNATURE", "ECDSA signature is missing r");
  const rLength = signature[offset + 1];
  if (rLength === undefined) throw new LumenError("INVALID_SIGNATURE", "ECDSA signature r length is missing");
  const r = signature.slice(offset + 2, offset + 2 + rLength);
  offset += 2 + rLength;
  if (signature[offset] !== 0x02) throw new LumenError("INVALID_SIGNATURE", "ECDSA signature is missing s");
  const sLength = signature[offset + 1];
  if (sLength === undefined) throw new LumenError("INVALID_SIGNATURE", "ECDSA signature s length is missing");
  const s = signature.slice(offset + 2, offset + 2 + sLength);
  return concatFixedInteger(r, s);
}

function concatFixedInteger(r: Uint8Array, s: Uint8Array): Uint8Array {
  const raw = new Uint8Array(64);
  raw.set(trimAndPadInteger(r), 0);
  raw.set(trimAndPadInteger(s), 32);
  return raw;
}

function trimAndPadInteger(value: Uint8Array): Uint8Array {
  const trimmed = value.length > 32 && value[0] === 0 ? value.slice(1) : value;
  if (trimmed.length > 32) throw new LumenError("INVALID_SIGNATURE", "ECDSA integer is too large");
  const output = new Uint8Array(32);
  output.set(trimmed, 32 - trimmed.length);
  return output;
}
