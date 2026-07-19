import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { buildLumenChannelUrl, buildLumenLaunchAssetUrl, buildLumenLaunchUrl, createLumenVerifiedDocument, parseLumenLaunchUrl, parseLumenUrl, verifyLumenBundle } from "../src/index.js";

const encoder = new TextEncoder();

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function sriFor(bytes: Uint8Array): string {
  return `sha256-${createHash("sha256").update(bytes).digest("base64")}`;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value as Record<string, unknown>).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`).join(",")}}`;
}

async function fixture(overrides: { assetBytes?: Uint8Array } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKeyDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const indexHtml = encoder.encode('<link rel="stylesheet" href="./assets/app.css"><script type="module" src="./assets/app.js"></script>');
  const assetBytes = overrides.assetBytes ?? encoder.encode("globalThis.lumenSmoke = true;");
  const styleBytes = encoder.encode("body { color: black; }");
  const manifestBytes = encoder.encode(JSON.stringify({
    schema: "lumen/static-web-release/1",
    version: "0.0.1",
    entrypoint: "index.html",
    assets: {
      "index.html": { sha256: sha256(indexHtml), length: indexHtml.byteLength, mediaType: "text/html" },
      "assets/app.css": { sha256: sha256(styleBytes), length: styleBytes.byteLength, mediaType: "text/css" },
      "assets/app.js": { sha256: sha256(assetBytes), length: assetBytes.byteLength, mediaType: "text/javascript" }
    }
  }));
  const runtimeBytes = encoder.encode(JSON.stringify({ schema: "example/runtime/1", value: "ok" }));
  const signed = {
    schema: "lumen/index/1",
    generation: 1,
    createdAt: "2026-07-17T00:00:00.000Z",
    expiresAt: "2027-07-17T00:00:00.000Z",
    notaries: [{
      id: "dev",
      algorithm: "ECDSA-P256-SHA256",
      publicKeySpkiBase64: Buffer.from(publicKeyDer).toString("base64"),
      publicKeySpkiSha256: sha256(publicKeyDer)
    }],
    targets: {
      "releases/0.0.1/manifest.json": { sha256: sha256(manifestBytes), length: manifestBytes.byteLength, mediaType: "application/json", schema: "lumen/static-web-release/1" },
      "runtime/example.json": { sha256: sha256(runtimeBytes), length: runtimeBytes.byteLength, mediaType: "application/json", schema: "example/runtime/1" }
    }
  };
  const signature = sign("sha256", encoder.encode(canonicalJson(signed)), privateKey).toString("base64");
  const indexBytes = encoder.encode(JSON.stringify({ signed, signatures: [{ notaryId: "dev", signatureBase64: signature }] }));
  const files = new Map<string, Uint8Array>([
    ["index.json", indexBytes],
    ["targets/releases/0.0.1/manifest.json", manifestBytes],
    ["targets/runtime/example.json", runtimeBytes],
    ["index.html", indexHtml],
    ["assets/app.css", styleBytes],
    ["assets/app.js", assetBytes]
  ]);
  return {
    bundleDigest: `sha256:${sha256(indexBytes)}`,
    files,
    fetch: async (input: RequestInfo | URL) => {
      const href = input instanceof Request ? input.url : input.toString();
      const path = new URL(href).pathname.replace(/^\/bundle\//, "");
      const bytes = files.get(path);
      return bytes === undefined ? new Response("not found", { status: 404 }) : new Response(Buffer.from(bytes));
    }
  };
}

async function channelFixture(overrides: {
  revokeActiveBundle?: boolean;
  revokedPublisherKeys?: readonly string[];
  revokedBundleDigests?: readonly string[];
  minimumBundleGeneration?: number;
} = {}) {
  const data = await fixture();
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKeyDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const signed = {
    schema: "lumen/channel/1",
    generation: 1,
    createdAt: "2026-07-17T00:00:00.000Z",
    expiresAt: "2027-07-17T00:00:00.000Z",
    roots: [{
      id: "root",
      algorithm: "ECDSA-P256-SHA256",
      publicKeySpkiBase64: Buffer.from(publicKeyDer).toString("base64"),
      publicKeySpkiSha256: sha256(publicKeyDer)
    }],
    activeRelease: {
      source: "https://example.test/bundle/",
      bundleDigest: data.bundleDigest,
      releasePath: "releases/0.0.1/manifest.json",
      runtimePath: "runtime/example.json"
    },
    ...(overrides.revokedPublisherKeys === undefined ? {} : { revokedPublisherKeys: overrides.revokedPublisherKeys }),
    ...(overrides.revokedBundleDigests === undefined && overrides.revokeActiveBundle !== true ? {} : {
      revokedBundleDigests: overrides.revokeActiveBundle === true ? [data.bundleDigest] : overrides.revokedBundleDigests
    }),
    ...(overrides.minimumBundleGeneration === undefined ? {} : { minimumBundleGeneration: overrides.minimumBundleGeneration })
  };
  const signature = sign("sha256", encoder.encode(canonicalJson(signed)), privateKey).toString("base64");
  data.files.set("channel.json", encoder.encode(JSON.stringify({ signed, signatures: [{ rootId: "root", signatureBase64: signature }] })));
  return {
    ...data,
    rootFingerprint: `sha256:${sha256(publicKeyDer)}`,
  };
}

describe("verifyLumenBundle", () => {
  it("verifies a hash-pinned bundle, embedded notary signature, release manifest, runtime target, and assets", async () => {
    const data = await fixture();

    const result = await verifyLumenBundle({
      source: "https://example.test/bundle/",
      bundleDigest: data.bundleDigest,
      releasePath: "releases/0.0.1/manifest.json",
      runtimePath: "runtime/example.json",
      fetch: data.fetch
    });

    expect(result.generation).toBe(1);
    expect(result.release.version).toBe("0.0.1");
    expect(result.runtimeBytes).toEqual(data.files.get("targets/runtime/example.json"));
    expect([...result.assets.keys()].sort()).toEqual(["assets/app.css", "assets/app.js", "index.html"]);
  });

  it("falls back to another public IPFS gateway for the same CID", async () => {
    const data = await fixture();
    const seen: string[] = [];
    const fetch = async (input: RequestInfo | URL) => {
      const href = input instanceof Request ? input.url : input.toString();
      seen.push(href);
      const url = new URL(href);
      if (url.hostname === "dweb.link") return new Response("gateway timeout", { status: 504 });
      const path = url.pathname.replace(/^\/ipfs\/bafyfixture\//, "");
      const bytes = data.files.get(path);
      return bytes === undefined ? new Response("not found", { status: 404 }) : new Response(Buffer.from(bytes));
    };

    const result = await verifyLumenBundle({
      source: "https://dweb.link/ipfs/bafyfixture/",
      bundleDigest: data.bundleDigest,
      releasePath: "releases/0.0.1/manifest.json",
      runtimePath: "runtime/example.json",
      fetch
    });

    expect(result.source).toBe("https://dweb.link/ipfs/bafyfixture/");
    expect(seen).toContain("https://dweb.link/ipfs/bafyfixture/index.json");
    expect(seen).toContain("https://ipfs.io/ipfs/bafyfixture/index.json");
    expect(result.release.version).toBe("0.0.1");
  });

  it("can verify one IPFS bundle from different gateways per signed target", async () => {
    const data = await fixture();
    const seen: string[] = [];
    const fetch = async (input: RequestInfo | URL) => {
      const href = input instanceof Request ? input.url : input.toString();
      seen.push(href);
      const url = new URL(href);
      if (url.hostname === "dweb.link") {
        if (url.pathname.endsWith("/index.json")) return fileResponse(data.files, "index.json");
        return new Response("gateway target timeout", { status: 504 });
      }
      if (url.hostname === "ipfs.io") {
        if (url.pathname.endsWith("/targets/releases/0.0.1/manifest.json")) return fileResponse(data.files, "targets/releases/0.0.1/manifest.json");
        return new Response("gateway target timeout", { status: 504 });
      }
      if (url.hostname === "gateway.pinata.cloud") {
        const path = url.pathname.replace(/^\/ipfs\/bafyfixture\//, "");
        return fileResponse(data.files, path);
      }
      return new Response("not ready", { status: 504 });
    };

    const result = await verifyLumenBundle({
      source: "https://dweb.link/ipfs/bafyfixture/",
      bundleDigest: data.bundleDigest,
      releasePath: "releases/0.0.1/manifest.json",
      runtimePath: "runtime/example.json",
      fetch
    });

    expect(result.release.version).toBe("0.0.1");
    expect(result.runtimeBytes).toEqual(data.files.get("targets/runtime/example.json"));
    expect(seen).toContain("https://dweb.link/ipfs/bafyfixture/index.json");
    expect(seen).toContain("https://ipfs.io/ipfs/bafyfixture/targets/releases/0.0.1/manifest.json");
    expect(seen).toContain("https://gateway.pinata.cloud/ipfs/bafyfixture/targets/runtime/example.json");
    expect(seen).toContain("https://gateway.pinata.cloud/ipfs/bafyfixture/assets/app.js");
  });

  it("selects a launch source that can serve every release asset", async () => {
    const data = await fixture();
    const seen: string[] = [];
    const fetch = async (input: RequestInfo | URL) => {
      const href = input instanceof Request ? input.url : input.toString();
      seen.push(href);
      const url = new URL(href);
      const path = fixtureGatewayPath(url);
      if (url.hostname === "dweb.link" && path === "assets/app.js") {
        return new Response("gateway target timeout", { status: 504 });
      }
      return fileResponse(data.files, path);
    };

    const result = await verifyLumenBundle({
      source: "https://dweb.link/ipfs/bafyfixture/",
      bundleDigest: data.bundleDigest,
      releasePath: "releases/0.0.1/manifest.json",
      fetch,
      requireLaunchSource: true
    });

    expect(result.source).toBe("https://bafyfixture.ipfs.dweb.link/");
    expect(seen).toContain("https://dweb.link/ipfs/bafyfixture/assets/app.js");
    expect(seen).toContain("https://bafyfixture.ipfs.dweb.link/assets/app.js");
  });

  it("refuses to launch when no single gateway can serve the whole app", async () => {
    const data = await fixture();
    const seen: string[] = [];
    const fetch = async (input: RequestInfo | URL) => {
      const href = input instanceof Request ? input.url : input.toString();
      seen.push(href);
      const url = new URL(href);
      const path = fixtureGatewayPath(url);
      if (path === "index.json" || path === "targets/releases/0.0.1/manifest.json") {
        return fileResponse(data.files, path);
      }
      if ((path === "index.html" || path === "assets/app.css") && (url.hostname === "dweb.link" || url.hostname === "ipfs.io" || url.hostname === "gateway.pinata.cloud")) {
        return fileResponse(data.files, path);
      }
      if (path === "assets/app.js" && (url.hostname === "bafyfixture.ipfs.dweb.link" || url.hostname === "w3s.link")) {
        return fileResponse(data.files, path);
      }
      return new Response("not available on this gateway", { status: 504 });
    };

    await expect(verifyLumenBundle({
      source: "https://dweb.link/ipfs/bafyfixture/",
      bundleDigest: data.bundleDigest,
      releasePath: "releases/0.0.1/manifest.json",
      fetch,
      requireLaunchSource: true
    })).rejects.toMatchObject({ code: "LAUNCH_UNAVAILABLE" });
    expect(seen.some((href) => new URL(href).hostname === "w3s.link")).toBe(false);
  });

  it("emits fetch progress for diagnostics", async () => {
    const data = await fixture();
    const events: string[] = [];

    await verifyLumenBundle({
      source: "https://example.test/bundle/",
      bundleDigest: data.bundleDigest,
      releasePath: "releases/0.0.1/manifest.json",
      fetch: data.fetch,
      onProgress: (event) => events.push(`${event.state}:${event.path}`)
    });

    expect(events).toContain("fetching:index.json");
    expect(events).toContain("verified:index.json");
    expect(events).toContain("verified:index.html");
    expect(events).toContain("verified:assets/app.js");
  });

  it("creates a verified launch document without changing the visible Lumen URL", async () => {
    const data = await fixture();

    const document = await createLumenVerifiedDocument({
      source: "https://example.test/bundle/",
      bundleDigest: data.bundleDigest,
      releasePath: "releases/0.0.1/manifest.json",
      runtimePath: "runtime/example.json",
      fetch: data.fetch
    });

    expect(document.result.release.entrypoint).toBe("index.html");
    expect(document.html).toContain('<base href="https://example.test/bundle/">');
    expect(document.html).toContain('src="./assets/app.js"');
  });

  it("launches with browser-enforced SRI for executable and stylesheet assets", async () => {
    const data = await fixture();

    const document = await createLumenVerifiedDocument({
      source: "https://example.test/bundle/",
      bundleDigest: data.bundleDigest,
      releasePath: "releases/0.0.1/manifest.json",
      fetch: data.fetch
    });

    expect(document.html).toContain(`src="./assets/app.js" integrity="${sriFor(data.files.get("assets/app.js")!)}" crossorigin="anonymous"`);
    expect(document.html).toContain(`href="./assets/app.css" integrity="${sriFor(data.files.get("assets/app.css")!)}" crossorigin="anonymous"`);
    expect(document.html).toContain('<script type="importmap">');
    const importMap = JSON.parse(document.html.match(/<script type="importmap">([^<]+)<\/script>/u)![1]!) as { integrity: Record<string, string> };
    expect(importMap.integrity["https://example.test/bundle/assets/app.js"]).toBe(sriFor(data.files.get("assets/app.js")!));
  });

  it("ignores a fast gateway response whose target digest does not match", async () => {
    const data = await fixture();
    const fetch = async (input: RequestInfo | URL) => {
      const href = input instanceof Request ? input.url : input.toString();
      const url = new URL(href);
      const path = url.pathname.replace(/^\/ipfs\/bafyfixture\//, "");
      if (url.hostname === "dweb.link" && path === "assets/app.js") {
        return new Response("tampered but fast");
      }
      return fileResponse(data.files, path);
    };

    const result = await verifyLumenBundle({
      source: "https://dweb.link/ipfs/bafyfixture/",
      bundleDigest: data.bundleDigest,
      releasePath: "releases/0.0.1/manifest.json",
      fetch
    });

    expect(new TextDecoder().decode(result.assets.get("assets/app.js"))).toBe("globalThis.lumenSmoke = true;");
  });

  it("times out a hanging gateway before trying the next source", async () => {
    const data = await fixture();
    const seen: string[] = [];
    const fetch = async (input: RequestInfo | URL) => {
      const href = input instanceof Request ? input.url : input.toString();
      seen.push(href);
      const url = new URL(href);
      if (url.hostname === "dweb.link") return await new Promise<Response>(() => {});
      const path = url.pathname.replace(/^\/ipfs\/bafyfixture\//, "");
      const bytes = data.files.get(path);
      return bytes === undefined ? new Response("not found", { status: 404 }) : new Response(Buffer.from(bytes));
    };

    const result = await verifyLumenBundle({
      source: "https://dweb.link/ipfs/bafyfixture/",
      bundleDigest: data.bundleDigest,
      releasePath: "releases/0.0.1/manifest.json",
      fetch,
      fetchTimeoutMs: 1
    });

    expect(result.source).toBe("https://dweb.link/ipfs/bafyfixture/");
    expect(seen).toContain("https://ipfs.io/ipfs/bafyfixture/index.json");
  });

  it("does not reference Node Buffer in browser-delivered code", async () => {
    const sources = [
      await readFile(new URL("../src/index.ts", import.meta.url), "utf8"),
      await readFile(new URL("../apps/loader/src/main.ts", import.meta.url), "utf8")
    ].join("\n");

    expect(sources).not.toMatch(/\bBuffer\b/u);
  });

  it("rejects an index whose digest does not match the launch link", async () => {
    const data = await fixture();

    await expect(verifyLumenBundle({
      source: "https://example.test/bundle/",
      bundleDigest: `sha256:${"0".repeat(64)}`,
      releasePath: "releases/0.0.1/manifest.json",
      fetch: data.fetch
    })).rejects.toMatchObject({ code: "DIGEST_MISMATCH" });
  });

  it("rejects an asset whose bytes do not match the signed release manifest", async () => {
    const data = await fixture();
    data.files.set("assets/app.js", encoder.encode("globalThis.tampered = true;"));

    await expect(verifyLumenBundle({
      source: "https://example.test/bundle/",
      bundleDigest: data.bundleDigest,
      releasePath: "releases/0.0.1/manifest.json",
      fetch: data.fetch
    })).rejects.toMatchObject({ code: "DIGEST_MISMATCH" });
  });

  it("verifies an active release through a root-signed channel", async () => {
    const data = await channelFixture();

    const result = await verifyLumenBundle({
      channel: "https://example.test/bundle/channel.json",
      root: data.rootFingerprint,
      fetch: data.fetch
    });

    expect(result.release.version).toBe("0.0.1");
    expect(result.runtimeBytes).toEqual(data.files.get("targets/runtime/example.json"));
  });

  it("rejects a channel whose active bundle digest is revoked", async () => {
    const revoked = await channelFixture({ revokeActiveBundle: true });

    await expect(verifyLumenBundle({
      channel: "https://example.test/bundle/channel.json",
      root: revoked.rootFingerprint,
      fetch: revoked.fetch
    })).rejects.toMatchObject({ code: "REVOKED" });
  });
});

function fileResponse(files: ReadonlyMap<string, Uint8Array>, path: string): Response {
  const bytes = files.get(path);
  return bytes === undefined ? new Response("not found", { status: 404 }) : new Response(new Uint8Array(bytes));
}

function fixtureGatewayPath(url: URL): string {
  return url.pathname.replace(/^\/ipfs\/bafyfixture\//, "").replace(/^\//u, "");
}

describe("Lumen launch links", () => {
  it("builds compact production launch links by default", () => {
    const url = buildLumenLaunchUrl({
      launcherUrl: "https://lumen.example/",
      ipfs: "bafyfixture",
      bundleDigest: "sha256:abc",
      releasePath: "releases/app.json",
      runtimePath: "runtime/app.json"
    });

    expect(url).toMatch(/^https:\/\/lumen\.example\/#l=v1\.[A-Za-z0-9_-]+$/u);
    expect(parseLumenLaunchUrl(url)).toEqual({
      source: "https://dweb.link/ipfs/bafyfixture/",
      bundleDigest: "sha256:abc",
      releasePath: "releases/app.json",
      runtimePath: "runtime/app.json"
    });
  });

  it("can still build and parse readable debug launch links", () => {
    const url = buildLumenLaunchUrl({
      launcherUrl: "https://lumen.example/",
      ipfs: "bafyfixture",
      bundleDigest: "sha256:abc",
      releasePath: "releases/app.json",
      runtimePath: "runtime/app.json",
      format: "debug"
    });

    expect(url).toBe("https://lumen.example/#cid=bafyfixture&digest=sha256%3Aabc&release=releases%2Fapp.json&runtime=runtime%2Fapp.json");
    expect(parseLumenLaunchUrl(url)).toEqual({
      source: "https://dweb.link/ipfs/bafyfixture/",
      bundleDigest: "sha256:abc",
      releasePath: "releases/app.json",
      runtimePath: "runtime/app.json"
    });
  });

  it("keeps parsing the original expanded launch parameters", () => {
    expect(parseLumenLaunchUrl("https://lumen.example/#ipfs=bafyfixture&bundleDigest=sha256:abc&releasePath=releases/app.json&runtimePath=runtime/app.json")).toEqual({
      source: "https://dweb.link/ipfs/bafyfixture/",
      bundleDigest: "sha256:abc",
      releasePath: "releases/app.json",
      runtimePath: "runtime/app.json"
    });
  });

  it("builds and parses compact channel links", () => {
    const url = buildLumenChannelUrl({
      launcherUrl: "https://lumen.example/",
      channel: "https://example.test/channel.json",
      root: "sha256:abc"
    });

    expect(url).toMatch(/^https:\/\/lumen\.example\/#ch=v1\.[A-Za-z0-9_-]+$/u);
    expect(parseLumenUrl(url)).toEqual({
      channel: "https://example.test/channel.json",
      root: "sha256:abc"
    });
  });
});

describe("buildLumenLaunchAssetUrl", () => {
  it("launches dweb IPFS path sources on the raw dweb subdomain gateway", () => {
    expect(buildLumenLaunchAssetUrl(
      "https://dweb.link/ipfs/bafyfixture/",
      "index.html"
    )).toBe("https://bafyfixture.ipfs.dweb.link/index.html");
  });

  it("does not launch web apps on the in-browser IPFS service-worker gateway", () => {
    expect(buildLumenLaunchAssetUrl(
      "https://bafyfixture.ipfs.inbrowser.link/",
      "index.html"
    )).toBe("https://bafyfixture.ipfs.dweb.link/index.html");
  });

  it("keeps ordinary HTTPS sources unchanged", () => {
    expect(buildLumenLaunchAssetUrl(
      "https://example.test/bundle/",
      "index.html"
    )).toBe("https://example.test/bundle/index.html");
  });
});
