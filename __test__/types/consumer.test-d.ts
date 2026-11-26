// Compile-time consumer contract for the published declarations.
//
// This file is type-checked by `pnpm typecheck` without `skipLibCheck`, so a
// declaration that names an undeclared type (which silently degrades every
// factory to `any`) fails the check instead of shipping.

import {
  compile,
  create,
  deserialize,
  fromFile,
  validate,
  type BinaryScanResult,
  type CompileResult,
  type MatchData,
  type RuleMatch,
  type YaraX,
} from "../../index.js";

// Every factory must resolve to the concrete YaraX class, not `any`.
const a: YaraX = compile('rule x { condition: false }');
const b: YaraX = create();
const c: YaraX = deserialize(Buffer.from("nope"));
const d: YaraX = fromFile("/tmp/none.yar");
const result: CompileResult = validate("rule x { condition: false }");

// @ts-expect-error an unknown member is an error, not `any`
a.thisMethodDoesNotExist(1, 2, 3);
// @ts-expect-error a YaraX is not a string
const s: string = a;

// Scan helpers keep their concrete return types.
const syncMatches: Array<RuleMatch> = a.scan(Buffer.from("x"));
const asyncMatches: Promise<Array<RuleMatch>> = a.scanAsync(Buffer.from("x"));
const binary: Promise<BinaryScanResult> = a.scanBinaryAsync(Buffer.from("x"));
const match: MatchData | undefined = syncMatches[0]?.matches[0];

void [b, c, d, result, asyncMatches, binary, match, s];
