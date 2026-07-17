import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { verifyLumenBundle } from "../src/index.js";

const encoder = new TextEncoder();

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value as Record<string, unknown>).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`).join(",")}}`;
}

async function fixture(overrides: { assetBytes?: Uint8Array } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKeyDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const indexHtml = encoder.encode('<script type="module" src="./assets/app.js"></script>');
  const assetBytes = overrides.assetBytes ?? encoder.encode("globalThis.lumenSmoke = true;");
  const manifestBytes = encoder.encode(JSON.stringify({
    schema: "lumen/static-web-release/1",
    version: "0.0.1",
    entrypoint: "index.html",
    assets: {
      "index.html": { sha256: sha256(indexHtml), length: indexHtml.byteLength, mediaType: "text/html" },
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
    expect([...result.assets.keys()].sort()).toEqual(["assets/app.js", "index.html"]);
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

    expect(result.source).toBe("https://ipfs.io/ipfs/bafyfixture/");
    expect(seen).toContain("https://dweb.link/ipfs/bafyfixture/index.json");
    expect(seen).toContain("https://ipfs.io/ipfs/bafyfixture/index.json");
    expect(result.release.version).toBe("0.0.1");
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

    expect(result.source).toBe("https://ipfs.io/ipfs/bafyfixture/");
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
});
