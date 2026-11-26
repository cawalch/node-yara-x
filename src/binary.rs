//! Flat binary match protocol for high-density match reporting.
//!
//! When rules match thousands of times, allocating individual V8 objects and
//! cloning strings creates significant GC pauses. This module serializes matches
//! into a flat, contiguous 24-byte record buffer and an indexed metadata catalog.

use crate::tasks::{BaseYaraTask, ScanTarget, TaskScanOptions};
use crate::types::{MatchData, RuleMatch, RuleMetadata, VariableMap};
use napi::bindgen_prelude::{Buffer, Object, ObjectFinalize, ObjectRef, ToNapiValue};
use napi::{Env, JsValue, Result, Task};
use napi_derive::napi;
use std::cell::RefCell;
use std::sync::Arc;
use yara_x::Rules;

/// A 24-byte fixed-size binary match record.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct BinaryMatchRecord {
  /// Index of the rule in `BinaryScanCatalog.rules`.
  pub rule_id: u32,
  /// Index of the pattern in `RuleInfo.patterns`.
  pub pattern_id: u32,
  /// Byte offset of the match in the input data.
  pub offset: u64,
  /// Length of the matched data in bytes.
  pub length: u32,
  /// Bit flags for the match. Bits 0-7 carry the XOR key when
  /// [`FLAG_XOR_KEY_PRESENT`] is set; all other bits are reserved and zero.
  pub flags: u32,
}

const _: () = assert!(std::mem::size_of::<BinaryMatchRecord>() == 24);

/// Re-handles a resolved object for the duration of the calling callback.
///
/// `ObjectRef::get_value` ties the handle it returns to the borrow of its `Env`
/// argument, while a `#[napi]` method returns a handle valid for the callback.
/// The underlying value is the same object, created in this environment.
fn rehandle<'env>(env: &Env, object: Object<'_>) -> Object<'env> {
  Object::from_raw(env.raw(), object.raw())
}

/// Set in [`BinaryMatchRecord::flags`] when the match was produced through an
/// XOR key, that is when the pattern was compiled with an `xor` modifier.
const FLAG_XOR_KEY_PRESENT: u32 = 1 << 8;

/// Mask selecting the XOR key from [`BinaryMatchRecord::flags`].
const XOR_KEY_MASK: u32 = 0xff;

/// Encodes a match's XOR key into the record flags.
fn encode_flags(xor_key: Option<u8>) -> u32 {
  match xor_key {
    Some(key) => FLAG_XOR_KEY_PRESENT | (key as u32 & XOR_KEY_MASK),
    None => 0,
  }
}

/// Decodes the XOR key from the record flags.
fn decode_xor_key(flags: u32) -> Option<u8> {
  if flags & FLAG_XOR_KEY_PRESENT != 0 {
    Some((flags & XOR_KEY_MASK) as u8)
  } else {
    None
  }
}

/// Catalog entry for a compiled rule.
#[napi(object)]
#[derive(Clone, Debug, PartialEq)]
pub struct RuleInfo {
  /// Rule identifier name.
  pub identifier: String,
  /// Namespace of the rule.
  pub namespace: String,
  /// Rule tags.
  pub tags: Vec<String>,
  /// Pattern identifiers: the ones that matched in a binary scan, or all
  /// declared patterns when obtained from `getRules()`.
  pub patterns: Vec<String>,
  /// Rule metadata as key-value pairs, matching `RuleMatch.meta`.
  #[napi(ts_type = "Record<string, string | number | boolean>")]
  pub meta: RuleMetadata,
}

/// Catalog indexing the rules and patterns present in a binary scan result.
#[napi(object)]
#[derive(Clone, Debug, PartialEq)]
pub struct BinaryScanCatalog {
  /// Indexed list of rules that matched.
  pub rules: Vec<RuleInfo>,
}

/// Result of a binary scan containing packed match records and metadata catalog.
#[napi(object)]
pub struct BinaryScanResult {
  /// Flat binary buffer containing 24-byte match records.
  pub buffer: Buffer,
  /// Total number of matches recorded.
  pub match_count: u32,
  /// Indexed catalog of matching rules and patterns.
  pub catalog: BinaryScanCatalog,
}

/// An accessor view over binary scan results.
///
/// The record buffer stays in one Rust allocation and `getOffset()` and friends
/// read 24 bytes of it per call, so no match data is copied. The `catalog`
/// object is built on first access and reused; `buffer` hands back a copy of
/// the record bytes.
#[napi(custom_finalize)]
pub struct BinaryMatchView {
  buffer: Buffer,
  match_count: u32,
  catalog: BinaryScanCatalog,
  /// JavaScript object for [`BinaryMatchView::catalog`], built on first access.
  ///
  /// Held as a reference rather than an `Object` because a handle may not
  /// outlive the `Env` it was read with; the reference is what keeps the built
  /// object alive between reads. `finalize` releases it, so the catalog is
  /// collectable with the view, and napi's leak check stays on to report a
  /// reference that outlives that path.
  catalog_js: RefCell<Option<ObjectRef>>,
}

impl ObjectFinalize for BinaryMatchView {
  /// Releases the catalog reference when the JavaScript object is collected.
  fn finalize(self, env: Env) -> Result<()> {
    if let Some(catalog) = self.catalog_js.borrow_mut().take() {
      catalog.unref(&env)?;
    }
    Ok(())
  }
}

#[napi]
impl BinaryMatchView {
  /// Creates a new `BinaryMatchView` from a `BinaryScanResult`.
  #[napi(constructor)]
  pub fn new(result: BinaryScanResult) -> Self {
    Self {
      buffer: result.buffer,
      match_count: result.match_count,
      catalog: result.catalog,
      catalog_js: RefCell::new(None),
    }
  }

  /// Total number of matches in the view.
  #[napi(getter)]
  pub fn match_count(&self) -> u32 {
    self.match_count
  }

  /// Metadata catalog of rules and patterns.
  ///
  /// Built on first read and handed back by reference, so repeated reads cost
  /// one dereference and `view.catalog === view.catalog`. The object is shared
  /// with every later read: treat it as read-only, and copy the parts you need
  /// to change.
  #[napi(getter, ts_return_type = "BinaryScanCatalog")]
  pub fn catalog<'env>(&self, env: Env) -> Result<Object<'env>> {
    if let Some(cached) = self.catalog_js.borrow().as_ref() {
      return Ok(rehandle(&env, cached.get_value(&env)?));
    }

    let mut slot = self.catalog_js.borrow_mut();
    // Raced with itself only if a getter reentered this callback; rebuilding
    // then would leak a reference, so re-check under the write borrow.
    if let Some(cached) = slot.as_ref() {
      return Ok(rehandle(&env, cached.get_value(&env)?));
    }

    let raw = unsafe { ToNapiValue::to_napi_value(env.raw(), self.catalog.clone()) }?;
    let created = Object::from_raw(env.raw(), raw).create_ref::<true>()?;
    let value = rehandle(&env, created.get_value(&env)?);
    *slot = Some(created);
    Ok(value)
  }

  /// Returns a copy of the flat binary match records buffer.
  ///
  /// Copies the records on every read; keep the returned buffer, or read the
  /// fields through `getOffset()` and friends, when the record set is large.
  #[napi(getter)]
  pub fn buffer(&self) -> Buffer {
    Buffer::from(self.buffer.as_ref())
  }

  fn read_record(&self, index: u32) -> Option<BinaryMatchRecord> {
    let offset = (index as usize).checked_mul(24)?;
    let slice = self.buffer.as_ref().get(offset..offset + 24)?;
    Some(BinaryMatchRecord {
      rule_id: u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]),
      pattern_id: u32::from_le_bytes([slice[4], slice[5], slice[6], slice[7]]),
      offset: u64::from_le_bytes([
        slice[8], slice[9], slice[10], slice[11], slice[12], slice[13], slice[14], slice[15],
      ]),
      length: u32::from_le_bytes([slice[16], slice[17], slice[18], slice[19]]),
      flags: u32::from_le_bytes([slice[20], slice[21], slice[22], slice[23]]),
    })
  }

  /// Gets the rule index for the match record at `index`.
  #[napi]
  pub fn get_rule_id(&self, index: u32) -> Option<u32> {
    self.read_record(index).map(|r| r.rule_id)
  }

  /// Gets the pattern index for the match record at `index`.
  #[napi]
  pub fn get_pattern_id(&self, index: u32) -> Option<u32> {
    self.read_record(index).map(|r| r.pattern_id)
  }

  /// Gets the byte offset in the scanned target for the match record at `index`.
  #[napi]
  pub fn get_offset(&self, index: u32) -> Option<i64> {
    self.read_record(index).map(|r| r.offset as i64)
  }

  /// Gets the byte length for the match record at `index`.
  #[napi]
  pub fn get_length(&self, index: u32) -> Option<u32> {
    self.read_record(index).map(|r| r.length)
  }

  /// Gets the reserved flags for the match record at `index`.
  #[napi]
  pub fn get_flags(&self, index: u32) -> Option<u32> {
    self.read_record(index).map(|r| r.flags)
  }

  /// Gets the XOR key for the match record at `index`, for patterns compiled
  /// with an `xor` modifier. Returns `null` for plain matches and out-of-range
  /// indexes.
  #[napi]
  pub fn get_xor_key(&self, index: u32) -> Option<u32> {
    self
      .read_record(index)
      .and_then(|r| decode_xor_key(r.flags))
      .map(u32::from)
  }

  /// Gets the rule metadata for the match record at `index`.
  #[napi]
  pub fn get_rule(&self, index: u32) -> Option<RuleInfo> {
    let record = self.read_record(index)?;
    self.catalog.rules.get(record.rule_id as usize).cloned()
  }

  /// Gets the pattern identifier for the match record at `index`.
  #[napi]
  pub fn get_pattern(&self, index: u32) -> Option<String> {
    let record = self.read_record(index)?;
    let rule = self.catalog.rules.get(record.rule_id as usize)?;
    rule.patterns.get(record.pattern_id as usize).cloned()
  }

  /// Slices the matched bytes out of the scanned source buffer.
  ///
  /// The view does not retain the source, so pass the bytes that were scanned.
  #[napi]
  pub fn get_slice(&self, index: u32, source: Buffer) -> Option<Buffer> {
    let offset = self.get_offset(index)? as usize;
    let length = self.get_length(index)? as usize;
    if offset.checked_add(length)? <= source.len() {
      Some(Buffer::from(&source[offset..offset + length]))
    } else {
      None
    }
  }

  /// Materializes the binary match records into the `RuleMatch` object graph.
  ///
  /// With `source`, fills `MatchData.data` (lossy UTF-8) and
  /// `MatchData.dataBytes` (exact bytes); without it, `data` is empty and
  /// `dataBytes` is absent. The view does not retain the source, so pass the
  /// bytes that were scanned.
  #[napi(ts_args_type = "source?: Buffer")]
  pub fn to_rule_matches<'a>(
    &self,
    env: Env,
    source: Option<Buffer>,
  ) -> Result<Vec<RuleMatch<'a>>> {
    if self.match_count == 0 || self.catalog.rules.is_empty() {
      return Ok(Vec::new());
    }

    let mut rule_matches_map: Vec<Vec<MatchData>> = vec![Vec::new(); self.catalog.rules.len()];
    let src_ref = source.as_ref().map(|b| b.as_ref());

    for i in 0..self.match_count {
      if let Some(record) = self.read_record(i) {
        let rule_idx = record.rule_id as usize;
        let pattern_idx = record.pattern_id as usize;

        if let Some(rule) = self.catalog.rules.get(rule_idx) {
          let pattern_identifier = rule.patterns.get(pattern_idx).cloned().unwrap_or_default();

          let offset = record.offset as i64;
          let length = record.length as i64;

          let (data, data_bytes) = if let Some(src) = src_ref {
            let start = record.offset as usize;
            let end = start.saturating_add(record.length as usize);
            if let Some(slice) = src.get(start..end) {
              (
                String::from_utf8_lossy(slice).into_owned(),
                Some(Buffer::from(slice)),
              )
            } else {
              (String::new(), None)
            }
          } else {
            (String::new(), None)
          };

          rule_matches_map[rule_idx].push(MatchData {
            offset,
            length,
            data,
            identifier: pattern_identifier,
            context_data: None,
            context_match_offset: None,
            xor_key: decode_xor_key(record.flags),
            data_bytes,
          });
        }
      }
    }

    let mut results = Vec::new();
    for (rule_idx, matches) in rule_matches_map.into_iter().enumerate() {
      if matches.is_empty() {
        continue;
      }
      let rule_info = &self.catalog.rules[rule_idx];
      let meta = rule_info.meta.to_object(&env)?;

      results.push(RuleMatch {
        rule_identifier: rule_info.identifier.clone(),
        namespace: rule_info.namespace.clone(),
        meta,
        tags: rule_info.tags.clone(),
        matches,
      });
    }

    Ok(results)
  }
}

/// Extracts binary match records and metadata catalog from scan results.
pub fn extract_binary_scan_results(
  results: yara_x::ScanResults,
) -> (Vec<u8>, u32, BinaryScanCatalog) {
  let matching_rules = results.matching_rules();
  let rule_count = matching_rules.len();

  if rule_count == 0 {
    return (Vec::new(), 0, BinaryScanCatalog { rules: Vec::new() });
  }

  let mut catalog_rules = Vec::with_capacity(rule_count);
  let mut total_matches = 0usize;

  // First pass: count matches and build catalog
  for rule in matching_rules {
    let mut patterns = Vec::new();
    for pattern in rule.patterns() {
      let count = pattern.matches().len();
      if count > 0 {
        patterns.push(pattern.identifier().to_string());
        total_matches += count;
      }
    }

    let tags = rule.tags().map(|t| t.identifier().to_string()).collect();

    catalog_rules.push(RuleInfo {
      identifier: rule.identifier().to_string(),
      namespace: rule.namespace().to_string(),
      tags,
      patterns,
      meta: RuleMetadata::from_rule(&rule),
    });
  }

  let mut bytes = Vec::with_capacity(total_matches * 24);

  // Second pass: pack binary records directly into byte buffer
  for (rule_id, rule) in results.matching_rules().enumerate() {
    let mut pattern_idx = 0u32;
    for pattern in rule.patterns() {
      let matches = pattern.matches();
      if matches.len() == 0 {
        continue;
      }

      for match_item in matches {
        let range = match_item.range();
        bytes.extend_from_slice(&(rule_id as u32).to_le_bytes());
        bytes.extend_from_slice(&pattern_idx.to_le_bytes());
        bytes.extend_from_slice(&(range.start as u64).to_le_bytes());
        bytes.extend_from_slice(&((range.end - range.start) as u32).to_le_bytes());
        bytes.extend_from_slice(&encode_flags(match_item.xor_key()).to_le_bytes());
      }
      pattern_idx += 1;
    }
  }

  (
    bytes,
    total_matches as u32,
    BinaryScanCatalog {
      rules: catalog_rules,
    },
  )
}

/// Intermediate thread-safe output for async binary scan tasks.
pub struct BinaryScanTaskOutput {
  pub bytes: Vec<u8>,
  pub match_count: u32,
  pub catalog: BinaryScanCatalog,
}

/// N-API task for asynchronous binary scanning.
pub struct BinaryScanTask {
  base: BaseYaraTask,
  target: ScanTarget,
}

impl BinaryScanTask {
  pub fn new(
    rules: Arc<Rules>,
    target: ScanTarget,
    variables: Option<VariableMap>,
    options: TaskScanOptions,
  ) -> Self {
    Self {
      base: BaseYaraTask::new(rules, variables, options),
      target,
    }
  }
}

impl Task for BinaryScanTask {
  type Output = BinaryScanTaskOutput;
  type JsValue = BinaryScanResult;

  fn compute(&mut self) -> Result<Self::Output> {
    self.base.with_scanner(|scanner| {
      let results = match &self.target {
        ScanTarget::Buffer(buf) => scanner.scan(buf.as_ref()),
        ScanTarget::File(path) => scanner.scan_file(std::path::Path::new(path)),
      }
      .map_err(crate::error::scan_error_to_napi)?;

      let (bytes, match_count, catalog) = extract_binary_scan_results(results);
      Ok(BinaryScanTaskOutput {
        bytes,
        match_count,
        catalog,
      })
    })
  }

  fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(BinaryScanResult {
      buffer: Buffer::from(output.bytes),
      match_count: output.match_count,
      catalog: output.catalog,
    })
  }
}
