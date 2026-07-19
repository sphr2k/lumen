export class LumenError extends Error {
    code;
    constructor(code, message) {
        super(message);
        this.code = code;
        this.name = "LumenError";
    }
}
const textDecoder = new TextDecoder();
const textEncoder = new TextEncoder();
export async function verifyLumenBundle(input) {
    if (isChannelInput(input)) {
        const channel = await fetchAndVerifyLumenChannel(input);
        const bundleInput = {
            ...channel.signed.activeRelease,
            ...(input.fetch === undefined ? {} : { fetch: input.fetch }),
            ...(input.fetchTimeoutMs === undefined ? {} : { fetchTimeoutMs: input.fetchTimeoutMs }),
            ...(input.requireLaunchSource === undefined ? {} : { requireLaunchSource: input.requireLaunchSource }),
            ...(input.onProgress === undefined ? {} : { onProgress: input.onProgress }),
        };
        const result = await verifyLumenBundle(bundleInput);
        enforceChannelRevocations(channel.signed, result);
        enforceChannelRollback(channel.signed);
        return result;
    }
    const request = input.fetch ?? fetch;
    const bundleInput = input;
    return await verifyLumenBundleFromSources({ ...bundleInput, sources: sourceCandidates(bundleInput.source), fetch: request });
}
export async function createLumenVerifiedDocument(input) {
    const result = await verifyLumenBundle({ ...input, requireLaunchSource: true });
    const entrypointBytes = result.assets.get(result.release.entrypoint);
    if (entrypointBytes === undefined)
        throw new LumenError("INVALID_RELEASE", `Release entrypoint asset is missing: ${result.release.entrypoint}`);
    const html = prepareLaunchHtml(textDecoder.decode(entrypointBytes), result.source);
    return { result, html };
}
async function verifyLumenBundleFromSources(input) {
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
    const assets = new Map();
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
        verifiedPublisher,
        release,
        ...(runtimeBytes === undefined ? {} : { runtimeBytes }),
        assets
    };
}
export function parseLumenUrl(url) {
    const parsed = new URL(url);
    const params = new URLSearchParams(parsed.hash.startsWith("#") ? parsed.hash.slice(1) : parsed.hash);
    const channel = params.get("channel");
    const root = params.get("root");
    if (channel !== null || root !== null) {
        if (channel === null || root === null)
            throw new LumenError("BAD_INPUT", "Channel launch URL requires channel and root");
        return { channel, root };
    }
    const packedChannel = params.get("ch");
    if (packedChannel !== null)
        return unpackChannelPayload(packedChannel);
    const packed = params.get("l");
    if (packed !== null)
        return unpackLaunchPayload(packed);
    const bundleDigest = params.get("digest") ?? params.get("bundleDigest");
    if (bundleDigest === null)
        throw new LumenError("BAD_INPUT", "Launch URL is missing digest");
    const source = params.get("source");
    const ipfs = params.get("cid") ?? params.get("ipfs");
    const resolvedSource = source ?? (ipfs === null ? undefined : `https://dweb.link/ipfs/${ipfs}/`);
    if (resolvedSource === undefined)
        throw new LumenError("BAD_INPUT", "Launch URL is missing source or cid");
    const releasePath = optionalParam(params, "release") ?? optionalParam(params, "releasePath");
    const runtimePath = optionalParam(params, "runtime") ?? optionalParam(params, "runtimePath");
    return {
        source: resolvedSource,
        bundleDigest,
        ...(releasePath === undefined ? {} : { releasePath }),
        ...(runtimePath === undefined ? {} : { runtimePath })
    };
}
export function parseLumenLaunchUrl(url) {
    const parsed = parseLumenUrl(url);
    if (isChannelInput(parsed))
        throw new LumenError("BAD_INPUT", "Expected immutable Lumen launch link, received channel link");
    return parsed;
}
export function buildLumenLaunchUrl(input) {
    const url = new URL(input.launcherUrl);
    const params = new URLSearchParams();
    if (input.format === "debug") {
        if (input.source !== undefined)
            params.set("source", input.source);
        if (input.ipfs !== undefined)
            params.set("cid", input.ipfs);
        params.set("digest", input.bundleDigest);
        if (input.releasePath !== undefined)
            params.set("release", input.releasePath);
        if (input.runtimePath !== undefined)
            params.set("runtime", input.runtimePath);
    }
    else {
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
export function buildLumenChannelUrl(input) {
    const url = new URL(input.launcherUrl);
    const params = new URLSearchParams();
    if (input.format === "debug") {
        params.set("channel", input.channel);
        params.set("root", input.root);
    }
    else {
        params.set("ch", packChannelPayload({ v: 1, c: input.channel, r: input.root }));
    }
    url.hash = params.toString();
    return url.toString();
}
export function buildLumenLaunchAssetUrl(source, path) {
    assertSafeRelativePath(path);
    const baseSource = ensureTrailingSlash(source);
    let parsed;
    try {
        parsed = new URL(baseSource);
    }
    catch {
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
function prepareLaunchHtml(html, source) {
    const rewrittenHtml = rewriteRootRelativeAssetUrls(html);
    const base = `<base href="${escapeHtmlAttribute(ensureTrailingSlash(source))}">`;
    if (/<head[^>]*>/iu.test(rewrittenHtml))
        return rewrittenHtml.replace(/<head([^>]*)>/iu, `<head$1>${base}`);
    return `${base}${rewrittenHtml}`;
}
function rewriteRootRelativeAssetUrls(html) {
    return html.replace(/\b(src|href)=("|')\/(assets\/[^"']+)(\2)/giu, (_match, attribute, quote, path) => {
        return `${attribute}=${quote}${path}${quote}`;
    });
}
function escapeHtmlAttribute(value) {
    return value.replace(/&/gu, "&amp;").replace(/"/gu, "&quot;").replace(/</gu, "&lt;");
}
function optionalParam(params, name) {
    const value = params.get(name);
    return value === null || value === "" ? undefined : value;
}
function packLaunchPayload(payload) {
    return `v1.${bytesToBase64Url(textEncoder.encode(canonicalJson(payload)))}`;
}
function packChannelPayload(payload) {
    return `v1.${bytesToBase64Url(textEncoder.encode(canonicalJson(payload)))}`;
}
function unpackLaunchPayload(value) {
    if (!value.startsWith("v1."))
        throw new LumenError("BAD_INPUT", "Unsupported Lumen launch payload version");
    let decoded;
    try {
        decoded = JSON.parse(textDecoder.decode(base64UrlToBytes(value.slice(3))));
    }
    catch {
        throw new LumenError("BAD_INPUT", "Lumen launch payload is not valid base64url JSON");
    }
    if (!isRecord(decoded) || decoded.v !== 1 || typeof decoded.d !== "string") {
        throw new LumenError("BAD_INPUT", "Lumen launch payload is invalid");
    }
    const source = typeof decoded.s === "string" ? decoded.s : undefined;
    const cid = typeof decoded.c === "string" ? decoded.c : undefined;
    const resolvedSource = source ?? (cid === undefined ? undefined : `https://dweb.link/ipfs/${cid}/`);
    if (resolvedSource === undefined)
        throw new LumenError("BAD_INPUT", "Lumen launch payload is missing source or cid");
    const releasePath = typeof decoded.r === "string" && decoded.r !== "" ? decoded.r : undefined;
    const runtimePath = typeof decoded.u === "string" && decoded.u !== "" ? decoded.u : undefined;
    return {
        source: resolvedSource,
        bundleDigest: decoded.d,
        ...(releasePath === undefined ? {} : { releasePath }),
        ...(runtimePath === undefined ? {} : { runtimePath })
    };
}
function unpackChannelPayload(value) {
    if (!value.startsWith("v1."))
        throw new LumenError("BAD_INPUT", "Unsupported Lumen channel payload version");
    let decoded;
    try {
        decoded = JSON.parse(textDecoder.decode(base64UrlToBytes(value.slice(3))));
    }
    catch {
        throw new LumenError("BAD_INPUT", "Lumen channel payload is not valid base64url JSON");
    }
    if (!isRecord(decoded) || decoded.v !== 1 || typeof decoded.c !== "string" || typeof decoded.r !== "string") {
        throw new LumenError("BAD_INPUT", "Lumen channel payload is invalid");
    }
    return { channel: decoded.c, root: decoded.r };
}
async function fetchAndVerifyLumenChannel(input) {
    const request = input.fetch ?? fetch;
    const channelBytes = await fetchBytes(request, input.channel, input.fetchTimeoutMs);
    const channel = parseChannel(channelBytes);
    await verifyChannelSignature(channel, input.root);
    assertFreshDates(channel.signed.createdAt, channel.signed.expiresAt, "Channel");
    return channel;
}
function parseChannel(bytes) {
    const value = parseJson(bytes, "INVALID_CHANNEL", "channel is not valid JSON");
    if (!isRecord(value) || !isRecord(value.signed) || !Array.isArray(value.signatures)) {
        throw new LumenError("INVALID_CHANNEL", "channel must contain signed and signatures");
    }
    const signed = value.signed;
    const activeRelease = signed.activeRelease;
    if (signed.schema !== "lumen/channel/1"
        || typeof signed.generation !== "number"
        || !Number.isSafeInteger(signed.generation)
        || signed.generation < 1
        || typeof signed.createdAt !== "string"
        || typeof signed.expiresAt !== "string"
        || !Array.isArray(signed.roots)
        || !isRecord(activeRelease)
        || typeof activeRelease.source !== "string"
        || typeof activeRelease.bundleDigest !== "string") {
        throw new LumenError("INVALID_CHANNEL", "channel signed object is invalid");
    }
    if (signed.roots.length === 0)
        throw new LumenError("INVALID_CHANNEL", "channel has no root keys");
    for (const root of signed.roots)
        assertNotaryShape(root, "channel root");
    if (activeRelease.releasePath !== undefined && typeof activeRelease.releasePath !== "string")
        throw new LumenError("INVALID_CHANNEL", "activeRelease.releasePath is invalid");
    if (activeRelease.runtimePath !== undefined && typeof activeRelease.runtimePath !== "string")
        throw new LumenError("INVALID_CHANNEL", "activeRelease.runtimePath is invalid");
    if (typeof activeRelease.releasePath === "string")
        assertSafeRelativePath(activeRelease.releasePath);
    if (typeof activeRelease.runtimePath === "string")
        assertSafeRelativePath(activeRelease.runtimePath);
    assertStringArrayOrUndefined(signed.revokedPublisherKeys, "revokedPublisherKeys");
    assertStringArrayOrUndefined(signed.revokedBundleDigests, "revokedBundleDigests");
    if (signed.minimumBundleGeneration !== undefined
        && (typeof signed.minimumBundleGeneration !== "number" || !Number.isSafeInteger(signed.minimumBundleGeneration) || signed.minimumBundleGeneration < 1)) {
        throw new LumenError("INVALID_CHANNEL", "minimumBundleGeneration is invalid");
    }
    return value;
}
async function verifyChannelSignature(channel, expectedRoot) {
    const expected = normalizeSha256Fingerprint(expectedRoot, "root");
    const acceptedRoots = channel.signed.roots.filter((root) => normalizeKeyFingerprint(root.publicKeySpkiSha256) === expected);
    if (acceptedRoots.length === 0)
        throw new LumenError("INVALID_SIGNATURE", "Channel does not contain the pinned root key");
    const payload = textEncoder.encode(canonicalJson(channel.signed));
    for (const signature of channel.signatures) {
        if (!isRecord(signature) || typeof signature.rootId !== "string" || typeof signature.signatureBase64 !== "string")
            continue;
        const root = acceptedRoots.find((candidate) => candidate.id === signature.rootId);
        if (root === undefined)
            continue;
        if (await verifyP256Signature(root, signature.signatureBase64, payload)) {
            return { id: root.id, publicKeySpkiSha256: normalizeKeyFingerprint(root.publicKeySpkiSha256) };
        }
    }
    throw new LumenError("INVALID_SIGNATURE", "No valid Lumen Channel signature found for the pinned root key");
}
function enforceChannelRevocations(channel, result) {
    const revokedBundles = new Set((channel.revokedBundleDigests ?? []).map((digest) => normalizeSha256Fingerprint(digest, "revoked bundle digest")));
    const activeDigest = normalizeSha256Fingerprint(channel.activeRelease.bundleDigest, "active release digest");
    if (revokedBundles.has(activeDigest))
        throw new LumenError("REVOKED", "Active release bundle digest is revoked by the Lumen Channel");
    const revokedKeys = new Set((channel.revokedPublisherKeys ?? []).map((key) => normalizeSha256Fingerprint(key, "revoked publisher key")));
    if (revokedKeys.has(normalizeKeyFingerprint(result.verifiedPublisher.publicKeySpkiSha256))) {
        throw new LumenError("REVOKED", "Active release publisher key is revoked by the Lumen Channel");
    }
    if (channel.minimumBundleGeneration !== undefined && result.generation < channel.minimumBundleGeneration) {
        throw new LumenError("REVOKED", "Active release generation is below the Lumen Channel minimum");
    }
}
function enforceChannelRollback(channel) {
    if (typeof localStorage === "undefined")
        return;
    const keyIds = channel.roots.map((root) => normalizeKeyFingerprint(root.publicKeySpkiSha256)).sort().join(",");
    const storageKey = `lumen:channel:${keyIds}`;
    const stored = Number.parseInt(localStorage.getItem(storageKey) ?? "0", 10);
    if (Number.isSafeInteger(stored) && stored > channel.generation) {
        throw new LumenError("INVALID_CHANNEL", "Lumen Channel generation rollback detected");
    }
    localStorage.setItem(storageKey, String(channel.generation));
}
function sourceCandidates(source) {
    const primary = ensureTrailingSlash(source);
    let url;
    try {
        url = new URL(primary);
    }
    catch {
        return [primary];
    }
    const match = /^\/ipfs\/([^/]+)\/?$/u.exec(url.pathname);
    if (match === null)
        return [primary];
    const cid = match[1];
    return unique([
        primary,
        `https://dweb.link/ipfs/${cid}/`,
        `https://${cid}.ipfs.dweb.link/`,
        `https://ipfs.io/ipfs/${cid}/`,
        `https://gateway.pinata.cloud/ipfs/${cid}/`,
        `https://w3s.link/ipfs/${cid}/`
    ]);
}
function unique(values) {
    return [...new Set(values)];
}
function parseIndex(bytes) {
    const value = parseJson(bytes, "INVALID_INDEX", "index.json is not valid JSON");
    if (!isRecord(value) || !isRecord(value.signed) || !Array.isArray(value.signatures)) {
        throw new LumenError("INVALID_INDEX", "index.json must contain signed and signatures");
    }
    const signed = value.signed;
    if (signed.schema !== "lumen/index/1" || typeof signed.generation !== "number" || !Array.isArray(signed.notaries) || !isRecord(signed.targets)) {
        throw new LumenError("INVALID_INDEX", "index signed object is invalid");
    }
    assertFreshDates(String(signed.createdAt), String(signed.expiresAt), "Index");
    for (const notary of signed.notaries)
        assertNotaryShape(notary, "index notary");
    return value;
}
function parseRelease(bytes) {
    const value = parseJson(bytes, "INVALID_RELEASE", "release manifest is not valid JSON");
    if (!isRecord(value) || value.schema !== "lumen/static-web-release/1" || typeof value.version !== "string" || typeof value.entrypoint !== "string" || !isRecord(value.assets)) {
        throw new LumenError("INVALID_RELEASE", "release manifest is invalid");
    }
    for (const [path, target] of Object.entries(value.assets)) {
        assertSafeRelativePath(path);
        assertTargetShape(target, path);
    }
    return value;
}
function parseJson(bytes, code, message) {
    try {
        return JSON.parse(textDecoder.decode(bytes));
    }
    catch {
        throw new LumenError(code, message);
    }
}
async function verifyIndexSignature(index) {
    const payload = textEncoder.encode(canonicalJson(index.signed));
    for (const signature of index.signatures) {
        const notary = index.signed.notaries.find((candidate) => candidate.id === signature.notaryId);
        if (notary === undefined)
            continue;
        const ok = await verifyP256Signature(notary, signature.signatureBase64, payload);
        if (ok)
            return { id: notary.id, publicKeySpkiSha256: normalizeKeyFingerprint(notary.publicKeySpkiSha256) };
    }
    throw new LumenError("INVALID_SIGNATURE", "No valid Lumen Index signature found");
}
async function fetchTarget(request, sources, targets, path, timeoutMs) {
    assertSafeRelativePath(path);
    const target = targets[path];
    if (target === undefined)
        throw new LumenError("INVALID_TARGET", `Target is not signed by index: ${path}`);
    assertTargetShape(target, path);
    const bytes = await fetchVerifiedBundlePath(request, sources, `targets/${path}`, timeoutMs, undefined, async (bytes) => {
        await assertTargetBytes(bytes, target, path);
    });
    return bytes;
}
async function fetchVerifiedBundlePath(request, sources, path, timeoutMs, onProgress, verifyBytes) {
    const failures = [];
    const errors = [];
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
                    if (settled)
                        return;
                    await verifyBytes(bytes);
                    if (settled)
                        return;
                    onProgress?.({ state: "verified", path, source, url, elapsedMs: Math.round(performanceNow() - started) });
                    settled = true;
                    resolve(bytes);
                }
                catch (error) {
                    if (settled)
                        return;
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
async function selectLaunchSource(request, sources, assets, timeoutMs, onProgress) {
    const failures = [];
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
            }
            catch (error) {
                const message = messageOf(error);
                failures.push(`${url}: ${message}`);
                onProgress?.({ state: "failed", path: `launch:${path}`, source, url, elapsedMs: Math.round(performanceNow() - started), message });
                return false;
            }
        }));
        if (checked.every(Boolean))
            return source;
    }
    throw new LumenError("LAUNCH_UNAVAILABLE", `Verified bundle bytes, but no single gateway can serve every launch asset: ${failures.join(" | ")}`);
}
async function fetchBytes(request, url, timeoutMs = 15_000) {
    let response;
    const controller = new AbortController();
    let timeout;
    let timedOut = false;
    const timeoutPromise = new Promise((_resolve, reject) => {
        timeout = setTimeout(() => {
            timedOut = true;
            controller.abort();
            reject(new LumenError("FETCH_FAILED", `Fetch timed out for ${url} after ${timeoutMs}ms`));
        }, timeoutMs);
    });
    try {
        response = await Promise.race([request(url, { signal: controller.signal }), timeoutPromise]);
    }
    catch (error) {
        if (timedOut)
            throw new LumenError("FETCH_FAILED", `Fetch timed out for ${url} after ${timeoutMs}ms`);
        throw new LumenError("FETCH_FAILED", `Fetch failed for ${url}: ${messageOf(error)}`);
    }
    finally {
        if (timeout !== undefined)
            clearTimeout(timeout);
    }
    if (!response.ok)
        throw new LumenError("FETCH_FAILED", `Fetch failed for ${url}: ${response.status}`);
    return new Uint8Array(await response.arrayBuffer());
}
function selectOnlyTarget(targets, schema) {
    const matches = Object.entries(targets).filter(([, target]) => target.schema === schema);
    if (matches.length !== 1)
        throw new LumenError("INVALID_TARGET", `Expected exactly one target with schema ${schema}`);
    return matches[0][0];
}
function assertTargetShape(value, path) {
    if (!isRecord(value) || typeof value.sha256 !== "string" || typeof value.length !== "number" || !Number.isSafeInteger(value.length) || value.length < 0) {
        throw new LumenError("INVALID_TARGET", `Target metadata is invalid for ${path}`);
    }
}
function assertNotaryShape(value, label) {
    if (!isRecord(value)
        || typeof value.id !== "string"
        || value.id.trim() === ""
        || value.algorithm !== "ECDSA-P256-SHA256"
        || typeof value.publicKeySpkiBase64 !== "string"
        || typeof value.publicKeySpkiSha256 !== "string") {
        throw new LumenError("INVALID_SIGNATURE", `${label} is invalid`);
    }
}
function assertStringArrayOrUndefined(value, label) {
    if (value !== undefined && (!Array.isArray(value) || value.some((entry) => typeof entry !== "string"))) {
        throw new LumenError("INVALID_CHANNEL", `${label} must be an array of strings`);
    }
}
function assertFreshDates(createdAt, expiresAt, label) {
    const created = Date.parse(createdAt);
    const expires = Date.parse(expiresAt);
    if (!Number.isFinite(created) || !Number.isFinite(expires) || expires <= created) {
        throw new LumenError(label === "Channel" ? "INVALID_CHANNEL" : "INVALID_INDEX", `${label} createdAt/expiresAt ordering is invalid`);
    }
    if (expires <= Date.now()) {
        throw new LumenError(label === "Channel" ? "INVALID_CHANNEL" : "INVALID_INDEX", `${label} is expired`);
    }
}
async function assertTargetBytes(bytes, target, label) {
    if (bytes.byteLength !== target.length) {
        throw new LumenError("DIGEST_MISMATCH", `${label} length mismatch`);
    }
    if (await sha256Hex(bytes) !== target.sha256) {
        throw new LumenError("DIGEST_MISMATCH", `${label} sha256 mismatch`);
    }
}
async function assertSha256Digest(bytes, digest, label) {
    const match = /^sha256:([0-9a-f]{64})$/u.exec(digest);
    if (match === null)
        throw new LumenError("BAD_INPUT", `${label} digest must be sha256:<hex>`);
    if (await sha256Hex(bytes) !== match[1])
        throw new LumenError("DIGEST_MISMATCH", `${label} sha256 mismatch`);
}
function assertSafeRelativePath(path) {
    if (path === "" || path.startsWith("/") || path.includes("..") || path.includes("\\") || /^https?:/iu.test(path)) {
        throw new LumenError("INVALID_TARGET", `Unsafe bundle path: ${path}`);
    }
}
function normalizeSha256Fingerprint(value, label) {
    const normalized = value.startsWith("sha256:") ? value : `sha256:${value}`;
    if (!/^sha256:[0-9a-f]{64}$/u.test(normalized))
        throw new LumenError("BAD_INPUT", `${label} must be sha256:<hex>`);
    return normalized;
}
function normalizeKeyFingerprint(value) {
    return normalizeSha256Fingerprint(value, "key fingerprint");
}
function ensureTrailingSlash(value) {
    return value.endsWith("/") ? value : `${value}/`;
}
async function verifyP256Signature(key, signatureBase64, payload) {
    const publicKeyBytes = base64ToBytes(key.publicKeySpkiBase64);
    if (await sha256Hex(publicKeyBytes) !== key.publicKeySpkiSha256) {
        throw new LumenError("INVALID_SIGNATURE", `Key ${key.id} public key fingerprint does not match`);
    }
    const publicKey = await crypto.subtle.importKey("spki", toArrayBuffer(publicKeyBytes), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, toArrayBuffer(derEcdsaSignatureToRaw(base64ToBytes(signatureBase64))), toArrayBuffer(payload));
}
async function sha256Hex(bytes) {
    const digest = await crypto.subtle.digest("SHA-256", toArrayBuffer(bytes));
    return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
function canonicalJson(value) {
    if (value === null || typeof value !== "object")
        return JSON.stringify(value);
    if (Array.isArray(value))
        return `[${value.map(canonicalJson).join(",")}]`;
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}
function isRecord(value) {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}
function isChannelInput(value) {
    return "channel" in value;
}
function messageOf(error) {
    return error instanceof Error ? error.message : String(error);
}
function performanceNow() {
    return typeof performance === "undefined" ? Date.now() : performance.now();
}
function base64ToBytes(value) {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
        bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
}
function bytesToBase64Url(bytes) {
    let binary = "";
    for (const byte of bytes)
        binary += String.fromCharCode(byte);
    return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
function base64UrlToBytes(value) {
    const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
    return base64ToBytes(padded);
}
function toArrayBuffer(bytes) {
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}
function derEcdsaSignatureToRaw(signature) {
    if (signature[0] !== 0x30)
        throw new LumenError("INVALID_SIGNATURE", "ECDSA signature is not DER encoded");
    let offset = 2;
    if (signature[1] === 0x81)
        offset = 3;
    if (signature[offset] !== 0x02)
        throw new LumenError("INVALID_SIGNATURE", "ECDSA signature is missing r");
    const rLength = signature[offset + 1];
    if (rLength === undefined)
        throw new LumenError("INVALID_SIGNATURE", "ECDSA signature r length is missing");
    const r = signature.slice(offset + 2, offset + 2 + rLength);
    offset += 2 + rLength;
    if (signature[offset] !== 0x02)
        throw new LumenError("INVALID_SIGNATURE", "ECDSA signature is missing s");
    const sLength = signature[offset + 1];
    if (sLength === undefined)
        throw new LumenError("INVALID_SIGNATURE", "ECDSA signature s length is missing");
    const s = signature.slice(offset + 2, offset + 2 + sLength);
    return concatFixedInteger(r, s);
}
function concatFixedInteger(r, s) {
    const raw = new Uint8Array(64);
    raw.set(trimAndPadInteger(r), 0);
    raw.set(trimAndPadInteger(s), 32);
    return raw;
}
function trimAndPadInteger(value) {
    const trimmed = value.length > 32 && value[0] === 0 ? value.slice(1) : value;
    if (trimmed.length > 32)
        throw new LumenError("INVALID_SIGNATURE", "ECDSA integer is too large");
    const output = new Uint8Array(32);
    output.set(trimmed, 32 - trimmed.length);
    return output;
}
