import { buildLumenLaunchAssetUrl, parseLumenLaunchUrl, verifyLumenBundle, type LumenVerifyInput } from "../../../src/index.js";
import "./style.css";

const form = document.querySelector<HTMLFormElement>("#verify-form");
const source = document.querySelector<HTMLInputElement>("#source");
const bundleDigest = document.querySelector<HTMLInputElement>("#bundleDigest");
const releasePath = document.querySelector<HTMLInputElement>("#releasePath");
const runtimePath = document.querySelector<HTMLInputElement>("#runtimePath");
const output = document.querySelector<HTMLPreElement>("#output");
const launch = document.querySelector<HTMLButtonElement>("#launch");

if (form === null || source === null || bundleDigest === null || releasePath === null || runtimePath === null || output === null || launch === null) {
  throw new Error("Loader DOM is incomplete");
}

const ui = { form, source, bundleDigest, releasePath, runtimePath, output, launch };

hydrateFromHash();

ui.form.addEventListener("submit", (event) => {
  event.preventDefault();
  void verify(false);
});

ui.launch.addEventListener("click", () => {
  void verify(true);
});

async function verify(shouldLaunch: boolean): Promise<void> {
  try {
    ui.output.textContent = "Verifying...";
    const result = await verifyLumenBundle(readForm());
    ui.output.textContent = JSON.stringify({
      state: "verified",
      generation: result.generation,
      release: result.release.version,
      assets: [...result.assets.keys()]
    }, null, 2);
    if (shouldLaunch) launchVerifiedAsset(result.source, result.release.entrypoint);
  } catch (error) {
    ui.output.textContent = JSON.stringify({
      state: "failed",
      code: error instanceof Error && "code" in error ? (error as { code: unknown }).code : "INTERNAL_ERROR",
      message: error instanceof Error ? error.message : String(error)
    }, null, 2);
  }
}

function hydrateFromHash(): void {
  if (location.hash.length <= 1) return;
  try {
    const parsed = parseLumenLaunchUrl(location.href);
    ui.source.value = parsed.source;
    ui.bundleDigest.value = parsed.bundleDigest;
    ui.releasePath.value = parsed.releasePath ?? "";
    ui.runtimePath.value = parsed.runtimePath ?? "";
  } catch (error) {
    ui.output.textContent = error instanceof Error ? error.message : String(error);
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
