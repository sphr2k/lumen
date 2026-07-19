export type LumenVerificationResult = Readonly<{
    source: string;
    generation: number;
    release: LumenStaticWebRelease;
    runtimeBytes?: Uint8Array;
    assets: ReadonlyMap<string, Uint8Array>;
}>;
export type LumenVerifyInput = Readonly<{
    source: string;
    bundleDigest: string;
    releasePath?: string;
    runtimePath?: string;
    fetchTimeoutMs?: number;
    fetch?: typeof fetch;
}>;
export declare class LumenError extends Error {
    readonly code: "BAD_INPUT" | "FETCH_FAILED" | "DIGEST_MISMATCH" | "INVALID_INDEX" | "INVALID_SIGNATURE" | "INVALID_TARGET" | "INVALID_RELEASE";
    constructor(code: "BAD_INPUT" | "FETCH_FAILED" | "DIGEST_MISMATCH" | "INVALID_INDEX" | "INVALID_SIGNATURE" | "INVALID_TARGET" | "INVALID_RELEASE", message: string);
}
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
export declare function verifyLumenBundle(input: LumenVerifyInput): Promise<LumenVerificationResult>;
export declare function parseLumenLaunchUrl(url: string): LumenVerifyInput;
export declare function buildLumenLaunchUrl(input: {
    launcherUrl: string;
    source?: string;
    ipfs?: string;
    bundleDigest: string;
    releasePath?: string;
    runtimePath?: string;
}): string;
export {};
