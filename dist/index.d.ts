export type LumenVerificationResult = Readonly<{
    source: string;
    generation: number;
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
export declare class LumenError extends Error {
    readonly code: "BAD_INPUT" | "FETCH_FAILED" | "DIGEST_MISMATCH" | "INVALID_INDEX" | "INVALID_SIGNATURE" | "INVALID_TARGET" | "INVALID_CHANNEL" | "REVOKED" | "INVALID_RELEASE" | "LAUNCH_UNAVAILABLE";
    constructor(code: "BAD_INPUT" | "FETCH_FAILED" | "DIGEST_MISMATCH" | "INVALID_INDEX" | "INVALID_SIGNATURE" | "INVALID_TARGET" | "INVALID_CHANNEL" | "REVOKED" | "INVALID_RELEASE" | "LAUNCH_UNAVAILABLE", message: string);
}
type LumenVerifiedKey = Readonly<{
    id: string;
    publicKeySpkiSha256: string;
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
export declare function verifyLumenBundle(input: LumenInput): Promise<LumenVerificationResult>;
export declare function createLumenVerifiedDocument(input: LumenInput): Promise<LumenVerifiedDocument>;
export declare function parseLumenUrl(url: string): LumenInput;
export declare function parseLumenLaunchUrl(url: string): LumenVerifyInput;
export declare function buildLumenLaunchUrl(input: {
    launcherUrl: string;
    source?: string;
    ipfs?: string;
    bundleDigest: string;
    releasePath?: string;
    runtimePath?: string;
    route?: string;
    format?: "compact" | "debug";
}): string;
export declare function buildLumenChannelUrl(input: {
    launcherUrl: string;
    channel: string;
    root: string;
    route?: string;
    format?: "compact" | "debug";
}): string;
export declare function buildLumenLaunchAssetUrl(source: string, path: string): string;
export {};
