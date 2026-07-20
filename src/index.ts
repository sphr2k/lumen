export type LumenVerificationResult = Readonly<{
  source: string;
  bundleDigest: string;
  generation: number;
  channelGeneration?: number;
  verifiedPublisher: LumenVerifiedKey;
  release: LumenStaticWebRelease;
  runtimeBytes?: Uint8Array;
  assets: ReadonlyMap<string, Uint8Array>;
}>;

export type LumenVerifiedDocument = Readonly<{
  result: LumenVerificationResult;
  html: string;
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
  route?: string;
  fetchTimeoutMs?: number;
  fetch?: typeof fetch;
  requireLaunchSource?: boolean;
  onProgress?: (event: LumenProgressEvent) => void;
}>;

export type LumenChannelInput = Readonly<{
  channel: string;
  root: string;
  route?: string;
  fetchTimeoutMs?: number;
  fetch?: typeof fetch;
  requireLaunchSource?: boolean;
  onProgress?: (event: LumenProgressEvent) => void;
}>;

export type LumenInput = LumenVerifyInput | LumenChannelInput;

export class LumenError extends Error {
  constructor(
    readonly code:
      | "BAD_INPUT"
      | "FETCH_FAILED"
      | "DIGEST_MISMATCH"
      | "INVALID_INDEX"
      | "INVALID_SIGNATURE"
      | "INVALID_TARGET"
      | "INVALID_CHANNEL"
      | "REVOKED"
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

type LumenVerifiedKey = Readonly<{
  id: string;
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

export type LumenReleasePointer = Readonly<{
  source: string;
  bundleDigest: string;
  releasePath?: string;
  runtimePath?: string;
}>;

type LumenChannelEnvelope = Readonly<{
  signed: LumenChannelSigned;
  signatures: readonly LumenChannelSignature[];
}>;

type LumenChannelSigned = Readonly<{
  schema: "lumen/channel/1";
  generation: number;
  createdAt: string;
  expiresAt: string;
  roots: readonly LumenNotary[];
  activeRelease: LumenReleasePointer;
  revokedPublisherKeys?: readonly string[];
  revokedBundleDigests?: readonly string[];
  minimumBundleGeneration?: number;
}>;

type LumenChannelSignature = Readonly<{
  rootId: string;
  signatureBase64: string;
}>;

type LumenLaunchPayload = Readonly<{
  v: 1;
  s?: string;
  c?: string;
  d: string;
  r?: string;
  u?: string;
  a?: string;
}>;

type LumenChannelPayload = Readonly<{
  v: 1;
  c: string;
  r: string;
  a?: string;
}>;

const textDecoder = new TextDecoder();
const textEncoder = new TextEncoder();

export async function verifyLumenBundle(input: LumenInput): Promise<LumenVerificationResult> {
  if (isChannelInput(input)) {
    const channel = await fetchAndVerifyLumenChannel(input);
    const bundleInput: LumenVerifyInput = {
      ...channel.signed.activeRelease,
      ...(input.fetch === undefined ? {} : { fetch: input.fetch }),
      ...(input.fetchTimeoutMs === undefined ? {} : { fetchTimeoutMs: input.fetchTimeoutMs }),
      ...(input.requireLaunchSource === undefined ? {} : { requireLaunchSource: input.requireLaunchSource }),
      ...(input.onProgress === undefined ? {} : { onProgress: input.onProgress }),
    };
    const result = await verifyLumenBundle(bundleInput);
    enforceChannelRevocations(channel.signed, result);
    enforceChannelRollback(channel.signed);
    return { ...result, channelGeneration: channel.signed.generation };
  }
  const request = input.fetch ?? fetch;
  const bundleInput: LumenVerifyInput = input;
  return await verifyLumenBundleFromSources({ ...bundleInput, sources: sourceCandidates(bundleInput.source), fetch: request });
}

export async function createLumenVerifiedDocument(input: LumenInput): Promise<LumenVerifiedDocument> {
  const result = await verifyLumenBundle({ ...input, requireLaunchSource: true });
  const entrypointBytes = result.assets.get(result.release.entrypoint);
  if (entrypointBytes === undefined) throw new LumenError("INVALID_RELEASE", `Release entrypoint asset is missing: ${result.release.entrypoint}`);
  const html = prepareLaunchHtml(textDecoder.decode(entrypointBytes), result, input.route);
  return { result, html };
}

async function verifyLumenBundleFromSources(input: LumenVerifyInput & { sources: readonly string[]; fetch: typeof fetch }): Promise<LumenVerificationResult> {
  const request = input.fetch;
  const sources = input.sources.map(ensureTrailingSlash);
  const timeoutMs = input.fetchTimeoutMs;
  const indexBytes = await fetchVerifiedBundlePath(request, sources, "index.json", timeoutMs, input.onProgress, async (bytes) => {
    await assertSha256Digest(bytes, input.bundleDigest, "index.json");
  });

  const index = parseIndex(indexBytes);
  const verifiedPublisher = await verifyIndexSignature(index);

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
    ? await selectLaunchSource(request, sources, release.assets, release.entrypoint, timeoutMs, input.onProgress)
    : undefined;

  return {
    source: launchSource ?? sources[0] ?? ensureTrailingSlash(input.source),
    bundleDigest: normalizeSha256Fingerprint(input.bundleDigest, "bundle digest"),
    generation: index.signed.generation,
    verifiedPublisher,
    release,
    ...(runtimeBytes === undefined ? {} : { runtimeBytes }),
    assets
  };
}

export function parseLumenUrl(url: string): LumenInput {
  const parsed = new URL(url);
  const params = new URLSearchParams(parsed.hash.startsWith("#") ? parsed.hash.slice(1) : parsed.hash);
  const channel = params.get("channel");
  const root = params.get("root");
  if (channel !== null || root !== null) {
    if (channel === null || root === null) throw new LumenError("BAD_INPUT", "Channel launch URL requires channel and root");
    const route = optionalLaunchRoute(params.get("route"));
    return { channel, root, ...(route === undefined ? {} : { route }) };
  }
  const packedChannel = params.get("ch");
  if (packedChannel !== null) return unpackChannelPayload(packedChannel);
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
  const route = optionalLaunchRoute(params.get("route"));
  return {
    source: resolvedSource,
    bundleDigest,
    ...(releasePath === undefined ? {} : { releasePath }),
    ...(runtimePath === undefined ? {} : { runtimePath }),
    ...(route === undefined ? {} : { route })
  };
}

export function parseLumenLaunchUrl(url: string): LumenVerifyInput {
  const parsed = parseLumenUrl(url);
  if (isChannelInput(parsed)) throw new LumenError("BAD_INPUT", "Expected immutable Lumen launch link, received channel link");
  return parsed;
}

export function buildLumenLaunchUrl(input: {
  launcherUrl: string;
  source?: string;
  ipfs?: string;
  bundleDigest: string;
  releasePath?: string;
  runtimePath?: string;
  route?: string;
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
    if (input.route !== undefined) params.set("route", input.route);
  } else {
    params.set("l", packLaunchPayload({
      v: 1,
      ...(input.source === undefined ? {} : { s: input.source }),
      ...(input.ipfs === undefined ? {} : { c: input.ipfs }),
      d: input.bundleDigest,
      ...(input.releasePath === undefined ? {} : { r: input.releasePath }),
      ...(input.runtimePath === undefined ? {} : { u: input.runtimePath }),
      ...(input.route === undefined ? {} : { a: input.route })
    }));
  }
  url.hash = params.toString();
  return url.toString();
}

export function buildLumenChannelUrl(input: {
  launcherUrl: string;
  channel: string;
  root: string;
  route?: string;
  format?: "compact" | "debug";
}): string {
  const url = new URL(input.launcherUrl);
  const params = new URLSearchParams();
  if (input.format === "debug") {
    params.set("channel", input.channel);
    params.set("root", input.root);
    if (input.route !== undefined) params.set("route", input.route);
  } else {
    params.set("ch", packChannelPayload({
      v: 1,
      c: input.channel,
      r: input.root,
      ...(input.route === undefined ? {} : { a: input.route })
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

function prepareLaunchHtml(html: string, result: LumenVerificationResult, route?: string): string {
  const launchSource = new URL(".", buildLumenLaunchAssetUrl(result.source, "index.html")).toString();
  const rewrittenHtml = injectImportMapIntegrity(
    injectSubresourceIntegrity(rewriteRootRelativeAssetUrls(html), result.release.assets),
    launchSource,
    result.release.assets
  );
  const base = `<base href="${escapeHtmlAttribute(launchSource)}">`;
  const releaseContext = {
    profile: "lumen/launch-context/1",
    kind: result.channelGeneration === undefined ? "release" : "channel",
    bundleDigest: result.bundleDigest,
    bundleGeneration: result.generation,
    ...(result.channelGeneration === undefined ? {} : { channelGeneration: result.channelGeneration }),
  };
  const launchContext = `<script>globalThis.__LUMEN_LAUNCH_CONTEXT__=${JSON.stringify(releaseContext)};${route === undefined ? "" : `globalThis.__LUMEN_LAUNCH_ROUTE__=${JSON.stringify(route)};`}</script>`;
  if (/<head[^>]*>/iu.test(rewrittenHtml)) return rewrittenHtml.replace(/<head([^>]*)>/iu, `<head$1>${base}${launchContext}`);
  return `${base}${launchContext}${rewrittenHtml}`;
}

function rewriteRootRelativeAssetUrls(html: string): string {
  return html.replace(/\b(src|href)=("|')\/(assets\/[^"']+)(\2)/giu, (_match: string, attribute: string, quote: string, path: string) => {
    return `${attribute}=${quote}${path}${quote}`;
  });
}

function injectSubresourceIntegrity(html: string, assets: Record<string, LumenTarget>): string {
  const withScripts = html.replace(/<script\b[^>]*\bsrc=(["'])([^"']+)\1[^>]*>/giu, (tag: string, _quote: string, rawSource: string) => {
    const target = assets[assetPathFromHtmlUrl(rawSource)];
    return target === undefined || !isScriptTarget(rawSource, target) ? tag : withHtmlAttribute(withHtmlAttribute(tag, "integrity", sriFromHex(target.sha256)), "crossorigin", "anonymous");
  });
  return withScripts.replace(/<link\b[^>]*\bhref=(["'])([^"']+)\1[^>]*>/giu, (tag: string, _quote: string, rawSource: string) => {
    if (!/\brel=(["'])[^"']*\bstylesheet\b[^"']*\1/iu.test(tag)) return tag;
    const target = assets[assetPathFromHtmlUrl(rawSource)];
    return target === undefined || !isStyleTarget(rawSource, target) ? tag : withHtmlAttribute(withHtmlAttribute(tag, "integrity", sriFromHex(target.sha256)), "crossorigin", "anonymous");
  });
}

function injectImportMapIntegrity(html: string, source: string, assets: Record<string, LumenTarget>): string {
  const integrity = Object.fromEntries(
    Object.entries(assets)
      .filter(([path, target]) => isScriptTarget(path, target))
      .map(([path, target]) => [new URL(path, ensureTrailingSlash(source)).toString(), sriFromHex(target.sha256)])
  );
  if (Object.keys(integrity).length === 0) return html;
  const importMap = `<script type="importmap">${JSON.stringify({ integrity })}</script>`;
  return /<script\b[^>]*type=(["'])module\1[^>]*>/iu.test(html)
    ? html.replace(/<script\b[^>]*type=(["'])module\1[^>]*>/iu, `${importMap}$&`)
    : `${importMap}${html}`;
}

function withHtmlAttribute(tag: string, name: string, value: string): string {
  const escaped = escapeHtmlAttribute(value);
  const pattern = new RegExp(`\\s${name}=(["'])[^"']*\\1`, "iu");
  if (pattern.test(tag)) return tag.replace(pattern, ` ${name}="${escaped}"`);
  return tag.replace(/>$/u, ` ${name}="${escaped}">`);
}

function assetPathFromHtmlUrl(value: string): string {
  return value.replace(/^\.\//u, "").replace(/^\//u, "");
}

function isScriptTarget(path: string, target: LumenTarget): boolean {
  return /\.(?:m?js)$/iu.test(path) || /(?:java|ecma)script/iu.test(target.mediaType ?? "");
}

function isStyleTarget(path: string, target: LumenTarget): boolean {
  return /\.css$/iu.test(path) || /^text\/css\b/iu.test(target.mediaType ?? "");
}

function sriFromHex(hex: string): string {
  return `sha256-${bytesToBase64(hexToBytes(hex))}`;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[\da-f]*$/iu.test(hex)) throw new LumenError("INVALID_TARGET", "Target SHA-256 must be hex encoded");
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  return bytes;
}

function escapeHtmlAttribute(value: string): string {
  return value.replace(/&/gu, "&amp;").replace(/"/gu, "&quot;").replace(/</gu, "&lt;");
}

function optionalParam(params: URLSearchParams, name: string): string | undefined {
  const value = params.get(name);
  return value === null || value === "" ? undefined : value;
}

function packLaunchPayload(payload: LumenLaunchPayload): string {
  return `v1.${bytesToBase64Url(textEncoder.encode(canonicalJson(payload)))}`;
}

function packChannelPayload(payload: LumenChannelPayload): string {
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
  const route = optionalLaunchRoute(decoded.a);
  return {
    source: resolvedSource,
    bundleDigest: decoded.d,
    ...(releasePath === undefined ? {} : { releasePath }),
    ...(runtimePath === undefined ? {} : { runtimePath }),
    ...(route === undefined ? {} : { route })
  };
}

function unpackChannelPayload(value: string): LumenChannelInput {
  if (!value.startsWith("v1.")) throw new LumenError("BAD_INPUT", "Unsupported Lumen channel payload version");
  let decoded: unknown;
  try {
    decoded = JSON.parse(textDecoder.decode(base64UrlToBytes(value.slice(3)))) as unknown;
  } catch {
    throw new LumenError("BAD_INPUT", "Lumen channel payload is not valid base64url JSON");
  }
  if (!isRecord(decoded) || decoded.v !== 1 || typeof decoded.c !== "string" || typeof decoded.r !== "string") {
    throw new LumenError("BAD_INPUT", "Lumen channel payload is invalid");
  }
  const route = optionalLaunchRoute(decoded.a);
  return { channel: decoded.c, root: decoded.r, ...(route === undefined ? {} : { route }) };
}

function optionalLaunchRoute(value: unknown): string | undefined {
  if (value === null || value === undefined || value === "") return undefined;
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//") || /[\u0000-\u001f\\]/u.test(value)) {
    throw new LumenError("BAD_INPUT", "Lumen launch route must be a same-app absolute path");
  }
  return value;
}

async function fetchAndVerifyLumenChannel(input: LumenChannelInput): Promise<LumenChannelEnvelope> {
  const request = input.fetch ?? fetch;
  const channelBytes = await fetchBytes(request, input.channel, input.fetchTimeoutMs);
  const channel = parseChannel(channelBytes);
  await verifyChannelSignature(channel, input.root);
  assertFreshDates(channel.signed.createdAt, channel.signed.expiresAt, "Channel");
  return channel;
}

function parseChannel(bytes: Uint8Array): LumenChannelEnvelope {
  const value = parseJson(bytes, "INVALID_CHANNEL", "channel is not valid JSON");
  if (!isRecord(value) || !isRecord(value.signed) || !Array.isArray(value.signatures)) {
    throw new LumenError("INVALID_CHANNEL", "channel must contain signed and signatures");
  }
  const signed = value.signed;
  const activeRelease = signed.activeRelease;
  if (
    signed.schema !== "lumen/channel/1"
    || typeof signed.generation !== "number"
    || !Number.isSafeInteger(signed.generation)
    || signed.generation < 1
    || typeof signed.createdAt !== "string"
    || typeof signed.expiresAt !== "string"
    || !Array.isArray(signed.roots)
    || !isRecord(activeRelease)
    || typeof activeRelease.source !== "string"
    || typeof activeRelease.bundleDigest !== "string"
  ) {
    throw new LumenError("INVALID_CHANNEL", "channel signed object is invalid");
  }
  if (signed.roots.length === 0) throw new LumenError("INVALID_CHANNEL", "channel has no root keys");
  for (const root of signed.roots) assertNotaryShape(root, "channel root");
  if (activeRelease.releasePath !== undefined && typeof activeRelease.releasePath !== "string") throw new LumenError("INVALID_CHANNEL", "activeRelease.releasePath is invalid");
  if (activeRelease.runtimePath !== undefined && typeof activeRelease.runtimePath !== "string") throw new LumenError("INVALID_CHANNEL", "activeRelease.runtimePath is invalid");
  if (typeof activeRelease.releasePath === "string") assertSafeRelativePath(activeRelease.releasePath);
  if (typeof activeRelease.runtimePath === "string") assertSafeRelativePath(activeRelease.runtimePath);
  assertStringArrayOrUndefined(signed.revokedPublisherKeys, "revokedPublisherKeys");
  assertStringArrayOrUndefined(signed.revokedBundleDigests, "revokedBundleDigests");
  if (
    signed.minimumBundleGeneration !== undefined
    && (typeof signed.minimumBundleGeneration !== "number" || !Number.isSafeInteger(signed.minimumBundleGeneration) || signed.minimumBundleGeneration < 1)
  ) {
    throw new LumenError("INVALID_CHANNEL", "minimumBundleGeneration is invalid");
  }
  return value as LumenChannelEnvelope;
}

async function verifyChannelSignature(channel: LumenChannelEnvelope, expectedRoot: string): Promise<LumenVerifiedKey> {
  const expected = normalizeSha256Fingerprint(expectedRoot, "root");
  const acceptedRoots = channel.signed.roots.filter((root) => normalizeKeyFingerprint(root.publicKeySpkiSha256) === expected);
  if (acceptedRoots.length === 0) throw new LumenError("INVALID_SIGNATURE", "Channel does not contain the pinned root key");
  const payload = textEncoder.encode(canonicalJson(channel.signed));
  for (const signature of channel.signatures) {
    if (!isRecord(signature) || typeof signature.rootId !== "string" || typeof signature.signatureBase64 !== "string") continue;
    const root = acceptedRoots.find((candidate) => candidate.id === signature.rootId);
    if (root === undefined) continue;
    if (await verifyP256Signature(root, signature.signatureBase64, payload)) {
      return { id: root.id, publicKeySpkiSha256: normalizeKeyFingerprint(root.publicKeySpkiSha256) };
    }
  }
  throw new LumenError("INVALID_SIGNATURE", "No valid Lumen Channel signature found for the pinned root key");
}

function enforceChannelRevocations(channel: LumenChannelSigned, result: LumenVerificationResult): void {
  const revokedBundles = new Set((channel.revokedBundleDigests ?? []).map((digest) => normalizeSha256Fingerprint(digest, "revoked bundle digest")));
  const activeDigest = normalizeSha256Fingerprint(channel.activeRelease.bundleDigest, "active release digest");
  if (revokedBundles.has(activeDigest)) throw new LumenError("REVOKED", "Active release bundle digest is revoked by the Lumen Channel");

  const revokedKeys = new Set((channel.revokedPublisherKeys ?? []).map((key) => normalizeSha256Fingerprint(key, "revoked publisher key")));
  if (revokedKeys.has(normalizeKeyFingerprint(result.verifiedPublisher.publicKeySpkiSha256))) {
    throw new LumenError("REVOKED", "Active release publisher key is revoked by the Lumen Channel");
  }
  if (channel.minimumBundleGeneration !== undefined && result.generation < channel.minimumBundleGeneration) {
    throw new LumenError("REVOKED", "Active release generation is below the Lumen Channel minimum");
  }
}

function enforceChannelRollback(channel: LumenChannelSigned): void {
  if (typeof localStorage === "undefined") return;
  const keyIds = channel.roots.map((root) => normalizeKeyFingerprint(root.publicKeySpkiSha256)).sort().join(",");
  const storageKey = `lumen:channel:${keyIds}`;
  const stored = Number.parseInt(localStorage.getItem(storageKey) ?? "0", 10);
  if (Number.isSafeInteger(stored) && stored > channel.generation) {
    throw new LumenError("INVALID_CHANNEL", "Lumen Channel generation rollback detected");
  }
  localStorage.setItem(storageKey, String(channel.generation));
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
    `https://gateway.pinata.cloud/ipfs/${cid}/`
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
  assertFreshDates(String(signed.createdAt), String(signed.expiresAt), "Index");
  for (const notary of signed.notaries) assertNotaryShape(notary, "index notary");
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

async function verifyIndexSignature(index: LumenIndexEnvelope): Promise<LumenVerifiedKey> {
  const payload = textEncoder.encode(canonicalJson(index.signed));
  for (const signature of index.signatures) {
    const notary = index.signed.notaries.find((candidate) => candidate.id === signature.notaryId);
    if (notary === undefined) continue;
    const ok = await verifyP256Signature(notary, signature.signatureBase64, payload);
    if (ok) return { id: notary.id, publicKeySpkiSha256: normalizeKeyFingerprint(notary.publicKeySpkiSha256) };
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
  for (const source of sources) {
    const url = new URL(path, source).toString();
    const started = performanceNow();
    onProgress?.({ state: "fetching", path, source, url });
    try {
      const bytes = await fetchBytes(request, url, timeoutMs);
      await verifyBytes(bytes);
      onProgress?.({ state: "verified", path, source, url, elapsedMs: Math.round(performanceNow() - started) });
      return bytes;
    } catch (error) {
      onProgress?.({ state: "failed", path, source, url, elapsedMs: Math.round(performanceNow() - started), message: messageOf(error) });
      errors.push(error);
      failures.push(`${url}: ${messageOf(error)}`);
    }
  }
  if (errors.length === 1 && errors[0] instanceof LumenError && errors[0].code !== "FETCH_FAILED") throw errors[0];
  throw new LumenError("FETCH_FAILED", `All repository sources failed for ${path}: ${failures.join(" | ")}`);
}

async function selectLaunchSource(
  request: typeof fetch,
  sources: readonly string[],
  assets: Record<string, LumenTarget>,
  entrypoint: string,
  timeoutMs: number | undefined,
  onProgress: ((event: LumenProgressEvent) => void) | undefined
): Promise<string> {
  const failures: string[] = [];
  const launchAssets = Object.entries(assets).filter(([path]) => path !== entrypoint);
  for (const source of sources) {
    const checked = await Promise.all(launchAssets.map(async ([path, target]) => {
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

function assertNotaryShape(value: unknown, label: string): asserts value is LumenNotary {
  if (
    !isRecord(value)
    || typeof value.id !== "string"
    || value.id.trim() === ""
    || value.algorithm !== "ECDSA-P256-SHA256"
    || typeof value.publicKeySpkiBase64 !== "string"
    || typeof value.publicKeySpkiSha256 !== "string"
  ) {
    throw new LumenError("INVALID_SIGNATURE", `${label} is invalid`);
  }
}

function assertStringArrayOrUndefined(value: unknown, label: string): void {
  if (value !== undefined && (!Array.isArray(value) || value.some((entry) => typeof entry !== "string"))) {
    throw new LumenError("INVALID_CHANNEL", `${label} must be an array of strings`);
  }
}

function assertFreshDates(createdAt: string, expiresAt: string, label: string): void {
  const created = Date.parse(createdAt);
  const expires = Date.parse(expiresAt);
  if (!Number.isFinite(created) || !Number.isFinite(expires) || expires <= created) {
    throw new LumenError(label === "Channel" ? "INVALID_CHANNEL" : "INVALID_INDEX", `${label} createdAt/expiresAt ordering is invalid`);
  }
  if (expires <= Date.now()) {
    throw new LumenError(label === "Channel" ? "INVALID_CHANNEL" : "INVALID_INDEX", `${label} is expired`);
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

function normalizeSha256Fingerprint(value: string, label: string): `sha256:${string}` {
  const normalized = value.startsWith("sha256:") ? value : `sha256:${value}`;
  if (!/^sha256:[0-9a-f]{64}$/u.test(normalized)) throw new LumenError("BAD_INPUT", `${label} must be sha256:<hex>`);
  return normalized as `sha256:${string}`;
}

function normalizeKeyFingerprint(value: string): `sha256:${string}` {
  return normalizeSha256Fingerprint(value, "key fingerprint");
}

function ensureTrailingSlash(value: string): string {
  return value.endsWith("/") ? value : `${value}/`;
}

async function verifyP256Signature(key: LumenNotary, signatureBase64: string, payload: Uint8Array): Promise<boolean> {
  const publicKeyBytes = base64ToBytes(key.publicKeySpkiBase64);
  if (await sha256Hex(publicKeyBytes) !== key.publicKeySpkiSha256) {
    throw new LumenError("INVALID_SIGNATURE", `Key ${key.id} public key fingerprint does not match`);
  }
  const publicKey = await crypto.subtle.importKey("spki", toArrayBuffer(publicKeyBytes), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  return await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    toArrayBuffer(derEcdsaSignatureToRaw(base64ToBytes(signatureBase64))),
    toArrayBuffer(payload)
  );
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

function isChannelInput(value: LumenInput): value is LumenChannelInput {
  return "channel" in value;
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
  return bytesToBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
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
