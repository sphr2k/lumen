import { createLumenVerifiedDocument, parseLumenUrl, verifyLumenBundle, type LumenInput, type LumenProgressEvent, type LumenVerifyInput } from "../../../src/index.js";
import "./style.css";

const form = document.querySelector<HTMLFormElement>("#verify-form");
const source = document.querySelector<HTMLInputElement>("#source");
const bundleDigest = document.querySelector<HTMLInputElement>("#bundleDigest");
const releasePath = document.querySelector<HTMLInputElement>("#releasePath");
const runtimePath = document.querySelector<HTMLInputElement>("#runtimePath");
const output = document.querySelector<HTMLPreElement>("#output");
const launch = document.querySelector<HTMLButtonElement>("#launch");
const verifyButton = document.querySelector<HTMLButtonElement>("#verify");
const retry = document.querySelector<HTMLButtonElement>("#retry");
const details = document.querySelector<HTMLDetailsElement>("#details");
const timeline = document.querySelector<HTMLOListElement>("#timeline");
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
  || verifyButton === null
  || retry === null
  || details === null
  || timeline === null
  || statusIcon === null
  || statusTitle === null
  || statusMessage === null
  || statusMeta === null
) {
  throw new Error("Loader DOM is incomplete");
}

const ui = { form, source, bundleDigest, releasePath, runtimePath, output, launch, verifyButton, retry, details, timeline, statusIcon, statusTitle, statusMessage, statusMeta };
let hashInput: LumenInput | undefined;

const launchInputLoaded = hydrateFromHash();
if (launchInputLoaded) {
  void verify(true);
} else {
  setStatus("manual", "Manual verification", "Paste a Lumen link or enter bundle details to verify an app.", "Advanced mode is intended for diagnostics and release testing.");
  setActionMode("manual");
  ui.details.open = true;
}

ui.form.addEventListener("submit", (event) => {
  event.preventDefault();
  void verify(false);
});

ui.form.addEventListener("input", () => {
  hashInput = undefined;
});

ui.launch.addEventListener("click", () => {
  void verify(true);
});

ui.verifyButton.addEventListener("click", () => {
  void verify(false);
});

ui.retry.addEventListener("click", () => {
  void verify(true);
});

async function verify(shouldLaunch: boolean): Promise<void> {
  setBusy(true);
  resetTimeline();
  try {
    setActionMode("busy");
    setStatus("verifying", "Verifying signed app", "Checking signed metadata and release assets before launch.", shouldLaunch ? "Looking for one gateway that can serve the whole app." : "Gateway responses may be mixed because this is verification only.");
    ui.output.textContent = "Verification started.\n";
    const loaded = shouldLaunch
      ? await createLumenVerifiedDocument({ ...readForm(), onProgress: reportProgress })
      : undefined;
    const result = loaded?.result ?? await verifyLumenBundle({
      ...readForm(),
      onProgress: reportProgress,
    });
    ui.output.textContent = JSON.stringify({
      state: "verified",
      generation: result.generation,
      release: result.release.version,
      launchSource: result.source,
      assets: [...result.assets.keys()]
    }, null, 2);
    if (shouldLaunch) {
      setStatus("verified", "Launching verified app", "The app bundle is authentic. Lumen is replacing this document with verified bytes.", `Keeping this Lumen URL · release ${result.release.version}`);
      window.setTimeout(() => {
        if (loaded !== undefined) launchVerifiedDocument(loaded.html);
      }, 250);
    } else {
      setStatus("verified", "Verified", "The bundle is authentic and all release assets match their signed hashes.", `Release ${result.release.version} · generation ${String(result.generation)}`);
      setActionMode("manual");
    }
  } catch (error) {
    const code = error instanceof Error && "code" in error ? String((error as { code: unknown }).code) : "INTERNAL_ERROR";
    if (code === "LAUNCH_UNAVAILABLE") {
      setStatus("failed", "Verified, not launchable yet", "The signed bytes checked out, but no single gateway could serve the whole app for launch.", "Retry after the IPFS gateways have caught up, or publish through a pinned gateway.");
    } else if (code === "FETCH_FAILED" && error instanceof Error && error.message.includes("All repository sources failed for index.json")) {
      setStatus("failed", "Bundle not available yet", "No public gateway could fetch the signed bundle index for this CID.", "Retry after IPFS propagation, or publish through a pinned gateway.");
    } else if (code === "FETCH_FAILED") {
      setStatus("failed", "Bundle retrieval failed", "Lumen could not fetch every signed file needed to verify this app.", "Open Advanced details for the exact failing gateway request.");
    } else {
      setStatus("failed", "Verification failed", "The app was not opened because Lumen could not verify every required byte.", "Open Advanced details for the exact failing request.");
    }
    ui.details.open = true;
    ui.output.textContent = JSON.stringify({
      state: "failed",
      code,
      message: error instanceof Error ? error.message : String(error)
    }, null, 2);
    setActionMode("failed");
  } finally {
    setBusy(false);
  }
}

function hydrateFromHash(): boolean {
  if (location.hash.length <= 1) return false;
  try {
    const parsed = parseLumenUrl(location.href);
    hashInput = parsed;
    if (isChannelInput(parsed)) {
      ui.source.value = parsed.channel;
      ui.bundleDigest.value = parsed.root;
      ui.releasePath.value = "";
      ui.runtimePath.value = "";
    } else {
      ui.source.value = parsed.source;
      ui.bundleDigest.value = parsed.bundleDigest;
      ui.releasePath.value = parsed.releasePath ?? "";
      ui.runtimePath.value = parsed.runtimePath ?? "";
    }
    return true;
  } catch (error) {
    setStatus("failed", "Invalid Lumen link", "The launch link is missing required verification parameters.", "Open Advanced details to inspect the parser error.");
    ui.details.open = true;
    ui.output.textContent = error instanceof Error ? error.message : String(error);
    return false;
  }
}

function readForm(): LumenInput {
  if (hashInput !== undefined) return hashInput;
  return {
    source: ui.source.value,
    bundleDigest: ui.bundleDigest.value,
    ...(ui.releasePath.value === "" ? {} : { releasePath: ui.releasePath.value }),
    ...(ui.runtimePath.value === "" ? {} : { runtimePath: ui.runtimePath.value })
  };
}

function isChannelInput(value: LumenInput): value is Exclude<LumenInput, LumenVerifyInput> {
  return "channel" in value;
}

function launchVerifiedDocument(html: string): void {
  const parsed = new DOMParser().parseFromString(html, "text/html");
  const scripts = Array.from(parsed.scripts).map((script) => ({
    attributes: Array.from(script.attributes).map((attribute) => [attribute.name, attribute.value] as const),
    inBody: script.closest("body") !== null,
    text: script.textContent ?? "",
  }));
  parsed.querySelectorAll("script").forEach((script) => { script.remove(); });

  const nextHtml = document.importNode(parsed.documentElement, true);
  document.replaceChild(nextHtml, document.documentElement);

  for (const script of scripts) {
    const executable = document.createElement("script");
    for (const [name, value] of script.attributes) executable.setAttribute(name, value);
    executable.textContent = script.text;
    (script.inBody ? document.body : document.head).append(executable);
  }
}

function setBusy(value: boolean): void {
  ui.form.querySelectorAll("button, input").forEach((element) => {
    (element as HTMLButtonElement | HTMLInputElement).disabled = value;
  });
  ui.launch.disabled = value;
  ui.verifyButton.disabled = value;
  ui.retry.disabled = value;
}

function setStatus(state: "manual" | "verifying" | "verified" | "failed", title: string, message: string, meta: string): void {
  ui.statusTitle.dataset.state = state;
  ui.statusIcon.dataset.state = state;
  ui.statusTitle.textContent = title;
  ui.statusMessage.textContent = message;
  ui.statusMeta.textContent = meta;
}

function setActionMode(mode: "manual" | "busy" | "failed"): void {
  ui.launch.hidden = mode !== "manual";
  ui.verifyButton.hidden = mode !== "manual";
  ui.retry.hidden = mode !== "failed";
}

function resetTimeline(): void {
  ui.timeline.replaceChildren();
}

function reportProgress(event: LumenProgressEvent): void {
  if (event.state === "fetching") {
    const label = event.path.startsWith("launch:")
      ? `Checking launch gateway for ${event.path.slice("launch:".length)}`
      : `Fetching ${event.path}`;
    setStatus("verifying", label, hostLabel(event.source), "Every accepted byte is checked against the signed bundle index.");
  }
  const item = document.createElement("li");
  item.dataset.state = event.state;
  item.textContent = [
    event.state === "fetching" ? "Trying" : event.state === "verified" ? "OK" : "Failed",
    event.path,
    hostLabel(event.source),
    event.elapsedMs === undefined ? "" : `${String(event.elapsedMs)}ms`,
    event.message === undefined ? "" : event.message,
  ].filter((part) => part !== "").join(" · ");
  ui.timeline.append(item);
}

function hostLabel(sourceUrl: string): string {
  try {
    return new URL(sourceUrl).host;
  } catch {
    return sourceUrl;
  }
}
