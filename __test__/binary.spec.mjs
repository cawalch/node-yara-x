import { describe, it } from 'node:test'
import assert from 'node:assert'
import fs from 'node:fs'
import path from 'node:path'
import { compile, BinaryMatchView } from '../index.js'

describe('Flat / Binary Match ABI', () => {
  const sampleRule = `
    rule DetectMalware {
      meta:
        author = "Security Team"
      strings:
        $str1 = "malicious_payload"
        $str2 = "c2_server"
      condition:
        $str1 or $str2
    }

    rule DetectSecondary {
      strings:
        $token = "SECRET_TOKEN"
      condition:
        $token
    }
  `

  describe('scanBinary (synchronous buffer)', () => {
    it('should return empty result when no rules match', () => {
      const scanner = compile(sampleRule)
      const data = Buffer.from('clean benign content with no triggers')
      const result = scanner.scanBinary(data)

      assert.strictEqual(result.matchCount, 0)
      assert.strictEqual(result.buffer.length, 0)
      assert.deepStrictEqual(result.catalog.rules, [])

      const view = new BinaryMatchView(result)
      assert.strictEqual(view.matchCount, 0)
      assert.strictEqual(view.getOffset(0), null)
      assert.strictEqual(view.getRule(0), null)
    })

    it('should correctly record matches, catalog, and binary records', () => {
      const scanner = compile(sampleRule)
      const data = Buffer.from('prefix---malicious_payload---c2_server---suffix')
      const result = scanner.scanBinary(data)

      assert.strictEqual(result.matchCount, 2)
      assert.strictEqual(result.buffer.length, 2 * 24) // 2 records * 24 bytes
      assert.strictEqual(result.catalog.rules.length, 1)

      const rule0 = result.catalog.rules[0]
      assert.strictEqual(rule0.identifier, 'DetectMalware')
      assert.deepStrictEqual(rule0.patterns, ['$str1', '$str2'])

      const view = new BinaryMatchView(result)
      assert.strictEqual(view.matchCount, 2)

      // First match ($str1 at offset 9, length 17)
      assert.strictEqual(view.getRuleId(0), 0)
      assert.strictEqual(view.getPatternId(0), 0)
      assert.strictEqual(view.getOffset(0), 9)
      assert.strictEqual(view.getLength(0), 17)
      assert.strictEqual(view.getPattern(0), '$str1')
      const slice1 = view.getSlice(0, data)
      assert.ok(slice1)
      assert.strictEqual(slice1.toString(), 'malicious_payload')

      // Second match ($str2 at offset 29, length 9)
      assert.strictEqual(view.getRuleId(1), 0)
      assert.strictEqual(view.getPatternId(1), 1)
      assert.strictEqual(view.getOffset(1), 29)
      assert.strictEqual(view.getLength(1), 9)
      assert.strictEqual(view.getPattern(1), '$str2')
      const slice2 = view.getSlice(1, data)
      assert.ok(slice2)
      assert.strictEqual(slice2.toString(), 'c2_server')

      // Out of bounds check
      assert.strictEqual(view.getOffset(2), null)
      assert.strictEqual(view.getLength(2), null)
      assert.strictEqual(view.getRule(2), null)
      assert.strictEqual(view.getPattern(2), null)
      assert.strictEqual(view.getSlice(2, data), null)
    })

    it('should support multiple rules and pattern indexing', () => {
      const scanner = compile(sampleRule)
      const data = Buffer.from('SECRET_TOKEN and malicious_payload')
      const result = scanner.scanBinary(data)

      assert.strictEqual(result.matchCount, 2)
      assert.strictEqual(result.catalog.rules.length, 2)

      const view = new BinaryMatchView(result)
      assert.strictEqual(view.matchCount, 2)

      // Verify each match references the correct rule and pattern
      const p0 = view.getPattern(0)
      const p1 = view.getPattern(1)
      const slice0 = view.getSlice(0, data).toString()
      const slice1 = view.getSlice(1, data).toString()

      assert.ok(
        (slice0 === 'malicious_payload' && slice1 === 'SECRET_TOKEN') ||
        (slice0 === 'SECRET_TOKEN' && slice1 === 'malicious_payload')
      )
    })

    it('should support scan-time variables', () => {
      const varRule = `
        rule VarCheck {
          strings:
            $s = "trigger_token"
          condition:
            $s and user_flag == "active"
        }
        rule ConditionOnly {
          condition:
            user_flag == "active"
        }
      `
      const scanner = compile(varRule, {
        defineVariables: { user_flag: 'inactive' },
      })
      const data = Buffer.from('hello trigger_token world')

      let res = scanner.scanBinary(data)
      assert.strictEqual(res.matchCount, 0)
      assert.strictEqual(res.catalog.rules.length, 0)

      res = scanner.scanBinary(data, { user_flag: 'active' })
      assert.strictEqual(res.matchCount, 1) // 1 pattern match
      assert.strictEqual(res.catalog.rules.length, 2) // 2 rules matched
      const idents = res.catalog.rules.map(r => r.identifier)
      assert.ok(idents.includes('VarCheck'))
      assert.ok(idents.includes('ConditionOnly'))
    })
  })

  describe('scanFileBinary (synchronous file)', () => {
    it('should scan files using binary ABI', () => {
      const scanner = compile(sampleRule)
      const tmpPath = path.join(process.cwd(), 'binary_test_sample.tmp')
      fs.writeFileSync(tmpPath, 'file header malicious_payload file footer')

      try {
        const result = scanner.scanFileBinary(tmpPath)
        assert.strictEqual(result.matchCount, 1)
        assert.strictEqual(result.catalog.rules[0].identifier, 'DetectMalware')

        const view = new BinaryMatchView(result)
        assert.strictEqual(view.getOffset(0), 12)
        assert.strictEqual(view.getLength(0), 17)
      } finally {
        if (fs.existsSync(tmpPath)) {
          fs.unlinkSync(tmpPath)
        }
      }
    })
  })

  describe('scanBinaryAsync & scanFileBinaryAsync', () => {
    it('should scan buffer asynchronously with binary ABI', async () => {
      const scanner = compile(sampleRule)
      const data = Buffer.from('hello c2_server world')
      const result = await scanner.scanBinaryAsync(data)

      assert.strictEqual(result.matchCount, 1)
      assert.strictEqual(result.catalog.rules[0].identifier, 'DetectMalware')

      const view = new BinaryMatchView(result)
      assert.strictEqual(view.getOffset(0), 6)
      assert.strictEqual(view.getLength(0), 9)
      assert.strictEqual(view.getSlice(0, data).toString(), 'c2_server')
    })

    it('should scan file asynchronously with binary ABI', async () => {
      const scanner = compile(sampleRule)
      const tmpPath = path.join(process.cwd(), 'binary_async_test.tmp')
      fs.writeFileSync(tmpPath, 'async file SECRET_TOKEN done')

      try {
        const result = await scanner.scanFileBinaryAsync(tmpPath)
        assert.strictEqual(result.matchCount, 1)
        assert.strictEqual(result.catalog.rules[0].identifier, 'DetectSecondary')

        const view = new BinaryMatchView(result)
        assert.strictEqual(view.getOffset(0), 11)
        assert.strictEqual(view.getLength(0), 12)
      } finally {
        if (fs.existsSync(tmpPath)) {
          fs.unlinkSync(tmpPath)
        }
      }
    })
  })

  describe('High-density match scale test', () => {
    it('should handle 5,000 matches in a single buffer with zero GC pressure', () => {
      const repeatRule = `
        rule RepeatPattern {
          strings:
            $chunk = "TARGET"
          condition:
            $chunk
        }
      `
      const scanner = compile(repeatRule)

      // Create a buffer containing 5,000 repetitions of "TARGET____" (10 bytes each)
      const matchCountExpected = 5000
      const chunkStr = 'TARGET____'
      const totalLen = matchCountExpected * chunkStr.length
      const buf = Buffer.alloc(totalLen)
      for (let i = 0; i < matchCountExpected; i++) {
        buf.write(chunkStr, i * chunkStr.length, 'utf-8')
      }

      const startTime = performance.now()
      const result = scanner.scanBinary(buf)
      const durationMs = performance.now() - startTime

      assert.strictEqual(result.matchCount, matchCountExpected)
      assert.strictEqual(result.buffer.length, matchCountExpected * 24)

      const view = new BinaryMatchView(result)
      assert.strictEqual(view.matchCount, matchCountExpected)

      // Spot check first, middle, and last records
      assert.strictEqual(view.getOffset(0), 0)
      assert.strictEqual(view.getLength(0), 6)
      assert.strictEqual(view.getSlice(0, buf).toString(), 'TARGET')

      const midIdx = Math.floor(matchCountExpected / 2)
      assert.strictEqual(view.getOffset(midIdx), midIdx * 10)
      assert.strictEqual(view.getLength(midIdx), 6)
      assert.strictEqual(view.getSlice(midIdx, buf).toString(), 'TARGET')

      const lastIdx = matchCountExpected - 1
      assert.strictEqual(view.getOffset(lastIdx), lastIdx * 10)
      assert.strictEqual(view.getLength(lastIdx), 6)
      assert.strictEqual(view.getSlice(lastIdx, buf).toString(), 'TARGET')

      // Also verify pure DataView direct memory access without BinaryMatchView method overhead
      const dv = new DataView(result.buffer.buffer, result.buffer.byteOffset, result.buffer.byteLength)
      for (let i = 0; i < 100; i++) {
        const offset = Number(dv.getBigUint64(i * 24 + 8, true))
        const length = dv.getUint32(i * 24 + 16, true)
        assert.strictEqual(offset, i * 10)
        assert.strictEqual(length, 6)
      }
    })
  })
})
