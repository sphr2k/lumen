#!/usr/bin/env bun
import { parseLumenLaunchUrl, verifyLumenBundle } from "../src/index.js";

async function main(): Promise<void> {
  const [command, value] = process.argv.slice(2);
  if (command !== "verify" || value === undefined) {
    console.log("Usage: lumen verify <lumen-launch-url>");
    process.exitCode = 1;
    return;
  }

  const input = parseLumenLaunchUrl(value);
  const result = await verifyLumenBundle(input);
  console.log(JSON.stringify({
    ok: true,
    generation: result.generation,
    release: result.release.version,
    assets: [...result.assets.keys()]
  }, null, 2));
}

main().catch((error: unknown) => {
  const record = error instanceof Error && "code" in error
    ? { ok: false, code: String((error as { code: unknown }).code), message: error.message }
    : { ok: false, code: "INTERNAL_ERROR", message: error instanceof Error ? error.message : String(error) };
  console.error(JSON.stringify(record, null, 2));
  process.exitCode = 1;
});
