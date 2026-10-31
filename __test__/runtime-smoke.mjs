// Verifies the Node-API addon loads and behaves the same outside Node.js.
// Run by the `runtimes` CI job under Bun and Deno; also runs under Node.
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const yarax = require("../index.js");

const runtime = globalThis.Bun
  ? `bun ${globalThis.Bun.version}`
  : globalThis.Deno
    ? `deno ${globalThis.Deno.version.deno}`
    : `node ${process.version}`;

const rules = yarax.compile(`
  rule Smoke {
    strings:
      $a = "malware" xor(0x01-0xff)
    condition:
      $a
  }
`);

const sample = Uint8Array.from(Buffer.from("malware"), (byte) => byte ^ 0x42);
const [match] = rules.scan(sample);
const view = new yarax.BinaryMatchView(rules.scanBinary(sample));

const checks = {
  "scan returns the matching rule": match?.ruleIdentifier === "Smoke",
  "xorKey from scan": match?.matches?.[0]?.xorKey === 0x42,
  "getXorKey from the binary ABI": view.getXorKey(0) === 0x42,
  ruleCount: rules.ruleCount === 1,
};

const failed = Object.entries(checks)
  .filter(([, ok]) => !ok)
  .map(([name]) => name);

if (failed.length > 0) {
  console.error(`${runtime}: FAILED ${failed.join(", ")}`);
  process.exit(1);
}

console.log(`${runtime}: ok`);
