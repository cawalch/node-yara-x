// Compile-time consumer contract for the published declarations.
//
// This file is type-checked by `pnpm typecheck` without `skipLibCheck`, so a
// declaration that names an undeclared type (which silently degrades every
// factory to `any`) fails the check instead of shipping.
//
// The unannotated probes below are deliberate: annotating a variable with
// `YaraX` would hide an `any` return, because `any` is assignable to it.

import {
  compile,
  create,
  deserialize,
  fromFile,
  validate,
  type BinaryScanResult,
  type CompileResult,
  type MatchData,
  type RuleInfo,
  type RuleMatch,
  type YaraX,
} from "../../index.js";

// Every factory must resolve to the concrete YaraX class, not `any`.
const a: YaraX = compile('rule x { condition: false }');
const b: YaraX = create();
const c: YaraX = deserialize(Buffer.from("nope"));
const d: YaraX = fromFile("/tmp/none.yar");
const result: CompileResult = validate("rule x { condition: false }");

// Unannotated results must reject unknown members. If a factory returned
// `any`, these directives would be unused and tsc would fail on them.
const rawCompile = compile('rule x { condition: false }');
const rawCreate = create();
const rawDeserialize = deserialize(Buffer.from("nope"));
const rawFromFile = fromFile("/tmp/none.yar");

// @ts-expect-error an unknown member is an error, not `any`
rawCompile.thisMethodDoesNotExist(1, 2, 3);
// @ts-expect-error an unknown member is an error, not `any`
rawCreate.thisMethodDoesNotExist(1, 2, 3);
// @ts-expect-error an unknown member is an error, not `any`
rawDeserialize.thisMethodDoesNotExist(1, 2, 3);
// @ts-expect-error an unknown member is an error, not `any`
rawFromFile.thisMethodDoesNotExist(1, 2, 3);

// @ts-expect-error a YaraX is not a string
const s: string = a;

// `options` must be structurally checked, not `any`.
// @ts-expect-error unknown compiler option
compile('rule x { condition: false }', { notAnOption: true });
// @ts-expect-error unknown compiler option
validate('rule x { condition: false }', { notAnOption: true });

// Rule metadata is typed on both the plain and binary paths.
const ruleInfo: RuleInfo = a.getRules()[0];
const ruleMeta: Record<string, string | number | boolean> = ruleInfo.meta;
const binaryMeta: Record<string, string | number | boolean> =
  a.scanBinary(Buffer.from("x")).catalog.rules[0].meta;

// defineVariable accepts typed globals, including bigint.
a.defineVariable("threshold", 42);
a.defineVariable("ratio", 1.5);
a.defineVariable("flag", true);
a.defineVariable("family", "42");
a.defineVariable("exact", 9007199254740993n);
// @ts-expect-error objects are not variable values
a.defineVariable("bad", {});

// Scan helpers keep their concrete return types.
const syncMatches: Array<RuleMatch> = a.scan(Buffer.from("x"));
const asyncMatches: Promise<Array<RuleMatch>> = a.scanAsync(Buffer.from("x"));
const binary: Promise<BinaryScanResult> = a.scanBinaryAsync(Buffer.from("x"));
const match: MatchData | undefined = syncMatches[0]?.matches[0];

// #286: the async entry points type `variables` exactly like the sync ones, so
// an invalid value is a compile error on every path, not just `scan()`.
// @ts-expect-error null is not an extern variable value
const badSync: Promise<Array<RuleMatch>> = a.scanAsync(Buffer.from("x"), { x: null });
// @ts-expect-error null is not an extern variable value
const badFileAsync = a.scanFileAsync("/tmp/x", { x: null });
// @ts-expect-error null is not an extern variable value
const badBatch = a.scanDirectory("/tmp", {}, { x: null });
// bigint is a valid extern variable value on both paths.
const bigintOk = a.scanAsync(Buffer.from("x"), { x: 9007199254740993n });

// #285: the async scan methods take an `AbortSignal` last, and a cancelled
// batch says so with the right field types rather than `any`.
const abortedSignal = new AbortController().signal;
const cancelledMatches: Promise<Array<RuleMatch>> = a.scanAsync(Buffer.from("x"), undefined, abortedSignal);
const cancelledBinary: Promise<BinaryScanResult> = a.scanBinaryAsync(Buffer.from("x"), undefined, abortedSignal);
const cancelledSweep: Promise<{ cancelled: boolean; skipped: number }> = a
  .scanFiles(["/tmp/x"], {}, null, abortedSignal)
  .then((r) => ({ cancelled: r.cancelled, skipped: r.cancelledFiles }));
// The signal stays optional, so existing calls keep compiling.
const stillOptional: Promise<Array<RuleMatch>> = a.scanAsync(Buffer.from("x"));
// @ts-expect-error the last argument is an AbortSignal, not a bare object
const badSignal = a.scanAsync(Buffer.from("x"), null, {});

// #286: `emitWasmFileAsync()` resolves to void, not `unknown`.
const wasmVoid: Promise<void> = a.emitWasmFileAsync("/tmp/none.wasm");
// @ts-expect-error a void resolution is not a number
const wasmNotUnknown: number = a.emitWasmFileAsync("/tmp/none.wasm").then((v) => v + 1);

void [b, c, d, result, rawCompile, rawCreate, rawDeserialize, rawFromFile];
void [asyncMatches, binary, match, s];
void [ruleMeta, binaryMeta];
void [badSync, badFileAsync, badBatch, bigintOk, wasmVoid, wasmNotUnknown];
void [cancelledMatches, cancelledBinary, cancelledSweep, stillOptional, badSignal];
