import { buildLumenLaunchAssetUrl, parseLumenLaunchUrl, verifyLumenBundle, type LumenVerifyInput } from "../../../src/index.js";
import "./style.css";

const form = document.querySelector<HTMLFormElement>("#verify-form");
const source = document.querySelector<HTMLInputElement>("#source");
const bundleDigest = document.querySelector<HTMLInputElement>("#bundleDigest");
const releasePath = document.querySelector<HTMLInputElement>("#releasePath");
const runtimePath = document.querySelector<HTMLInputElement>("#runtimePath");
const output = document.querySelector<HTMLPreElement>("#output");
const launch = document.querySelector<HTMLButtonElement>("#launch");
const retry = document.querySelector<HTMLButtonElement>("#retry");
const details = document.querySelector<HTMLDetailsElement>("#details");
const statusIcon = document.querySelector<HTMLDivElement>("#status-icon");
const statusTitle = document.querySelector<HTMLHeadingElement>("#status-title");
const statusMessage = document.querySelector<HTMLParagraphElement>("#status-message");
const statusMeta = document.querySelector<HTMLParagraphElement>("#status-meta");

if (
  form === null
  || source === null
  || bundleDigest === null
  || releasePath === null
  || runtimePath === null
  || output === null
  || launch === null
  || retry === null
  || details === null
  || statusIcon === null
  || statusTitle === null
  || statusMessage === null
  || statusMeta === null
) {
  throw new Error("Loader DOM is incomplete");
}

const ui = { form, source, bundleDigest, releasePath, runtimePath, output, launch, retry, details, statusIcon, statusTitle, statusMessage, statusMeta };

const launchInputLoaded = hydrateFromHash();
if (launchInputLoaded) {
  void verify(true);
} else {
  setStatus("manual", "Manual verification", "Paste a Lumen link or enter bundle details to verify an app.", "Advanced mode is intended for diagnostics and release testing.");
  ui.details.open = true;
}

ui.form.addEventListener("submit", (event) => {
  event.preventDefault();
  void verify(false);
});

ui.launch.addEventListener("click", () => {
  void verify(true);
});

ui.retry.addEventListener("click", () => {
  void verify(true);
});

async function verify(shouldLaunch: boolean): Promise<void> {
  setBusy(true);
  try {
    setStatus("verifying", "Verifying signed app", "Checking the bundle digest, signature, runtime configuration, and release assets.", "This usually takes a few seconds. Fresh IPFS content can take a little longer.");
    ui.output.textContent = "Verifying signed bundle...\n";
    const result = await verifyLumenBundle(readForm());
    ui.output.textContent = JSON.stringify({
      state: "verified",
      generation: result.generation,
      release: result.release.version,
      assets: [...result.assets.keys()]
    }, null, 2);
    if (shouldLaunch) {
      setStatus("verified", "Verified", "The app bundle is authentic. Opening the verified app now.", `Release ${result.release.version} · generation ${String(result.generation)}`);
      window.setTimeout(() => launchVerifiedAsset(result.source, result.release.entrypoint), 250);
    } else {
      setStatus("verified", "Verified", "The bundle is authentic and all release assets match their signed hashes.", `Release ${result.release.version} · generation ${String(result.generation)}`);
    }
  } catch (error) {
    setStatus("failed", "Verification failed", "The app was not opened because Lumen could not verify every required byte.", "Open Advanced details for the exact failing request.");
    ui.details.open = true;
    ui.output.textContent = JSON.stringify({
      state: "failed",
      code: error instanceof Error && "code" in error ? (error as { code: unknown }).code : "INTERNAL_ERROR",
      message: error instanceof Error ? error.message : String(error)
    }, null, 2);
  } finally {
    setBusy(false);
  }
}

function hydrateFromHash(): boolean {
  if (location.hash.length <= 1) return false;
  try {
    const parsed = parseLumenLaunchUrl(location.href);
    ui.source.value = parsed.source;
    ui.bundleDigest.value = parsed.bundleDigest;
    ui.releasePath.value = parsed.releasePath ?? "";
    ui.runtimePath.value = parsed.runtimePath ?? "";
    return true;
  } catch (error) {
    setStatus("failed", "Invalid Lumen link", "The launch link is missing required verification parameters.", "Open Advanced details to inspect the parser error.");
    ui.details.open = true;
    ui.output.textContent = error instanceof Error ? error.message : String(error);
    return false;
  }
}

function readForm(): LumenVerifyInput {
  return {
    source: ui.source.value,
    bundleDigest: ui.bundleDigest.value,
    ...(ui.releasePath.value === "" ? {} : { releasePath: ui.releasePath.value }),
    ...(ui.runtimePath.value === "" ? {} : { runtimePath: ui.runtimePath.value })
  };
}

function launchVerifiedAsset(source: string, path: string): void {
  location.assign(buildLumenLaunchAssetUrl(source, path));
}

function setBusy(value: boolean): void {
  ui.form.querySelectorAll("button, input").forEach((element) => {
    (element as HTMLButtonElement | HTMLInputElement).disabled = value;
  });
  ui.retry.hidden = value || ui.statusTitle.dataset.state !== "failed";
}

function setStatus(state: "manual" | "verifying" | "verified" | "failed", title: string, message: string, meta: string): void {
  ui.statusTitle.dataset.state = state;
  ui.statusIcon.dataset.state = state;
  ui.statusTitle.textContent = title;
  ui.statusMessage.textContent = message;
  ui.statusMeta.textContent = meta;
  ui.retry.hidden = state !== "failed";
}
