//! Type definitions for YARA-X Node.js bindings.
//!
//! This module contains all the data structures used for interfacing between
//! Node.js and the YARA-X Rust library, including match results, compiler options,
//! and diagnostic information.

use napi::bindgen_prelude::{Buffer, Object};
use napi_derive::napi;
use std::collections::HashMap;
use yara_x::MetaValue;

/// A map of variable names to their values.
pub type VariableMap = HashMap<String, VariableValue>;

/// A YARA global variable value.
#[derive(Debug, Clone, PartialEq)]
pub enum VariableValue {
  /// A boolean value.
  Bool(bool),
  /// An integer value.
  Integer(i64),
  /// A floating-point value.
  Float(f64),
  /// A string value.
  String(String),
}

/// Accumulated timing for one rule, as reported by `getSlowestRules()`.
#[napi(object)]
#[derive(Debug, Clone, PartialEq)]
pub struct RuleProfile {
  /// Namespace the rule belongs to.
  pub namespace: String,
  /// Rule identifier.
  pub identifier: String,
  /// Milliseconds spent matching the rule's patterns.
  pub pattern_matching_ms: f64,
  /// Milliseconds spent executing the rule's condition.
  pub condition_ms: f64,
}

/// A YARA rule source and the namespace it belongs to.
#[napi(object)]
#[derive(Debug, Clone, PartialEq)]
pub struct RuleSource {
  /// The YARA rule source code.
  pub source: String,
  /// The namespace for the source. `None` means the default namespace.
  pub namespace: Option<String>,
}

/// Represents a match found by a YARA rule pattern.
///
/// Contains information about where the match occurred and what data was matched.
#[napi(object)]
pub struct MatchData {
  /// The offset of the match in the scanned data.
  pub offset: i64,
  /// The length of the matched data.
  pub length: i64,
  /// The matched data decoded as a UTF-8 string.
  ///
  /// Invalid UTF-8 becomes replacement characters, so this is lossy. Use
  /// [`data_bytes`](MatchData::data_bytes) when the exact matched bytes matter.
  pub data: String,
  /// The identifier of the pattern that matched.
  pub identifier: String,
  /// The context around the matched data, if match_context_size is set.
  pub context_data: Option<String>,
  /// The start offset of the actual match within the context data.
  pub context_match_offset: Option<i64>,
  /// The XOR key that produced this match, when the pattern was compiled with an
  /// `xor` modifier. Absent for plain matches.
  pub xor_key: Option<u8>,
  /// The exact matched bytes, byte-for-byte.
  ///
  /// Present whenever the scanner has the matched data (always for `scan`
  /// results, and for `toRuleMatches()` when a source buffer is supplied).
  /// Unlike `data`, this round-trips binary patterns that match invalid
  /// UTF-8.
  pub data_bytes: Option<Buffer>,
}

impl Clone for MatchData {
  fn clone(&self) -> Self {
    Self {
      offset: self.offset,
      length: self.length,
      data: self.data.clone(),
      identifier: self.identifier.clone(),
      context_data: self.context_data.clone(),
      context_match_offset: self.context_match_offset,
      xor_key: self.xor_key,
      data_bytes: self
        .data_bytes
        .as_ref()
        .map(|bytes| Buffer::from(bytes.as_ref())),
    }
  }
}

impl PartialEq for MatchData {
  fn eq(&self, other: &Self) -> bool {
    self.offset == other.offset
      && self.length == other.length
      && self.data == other.data
      && self.identifier == other.identifier
      && self.context_data == other.context_data
      && self.context_match_offset == other.context_match_offset
      && self.xor_key == other.xor_key
      && match (&self.data_bytes, &other.data_bytes) {
        (Some(a), Some(b)) => a.as_ref() == b.as_ref(),
        (None, None) => true,
        _ => false,
      }
  }
}

impl std::fmt::Debug for MatchData {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("MatchData")
      .field("offset", &self.offset)
      .field("length", &self.length)
      .field("data", &self.data)
      .field("identifier", &self.identifier)
      .field("context_data", &self.context_data)
      .field("context_match_offset", &self.context_match_offset)
      .field("xor_key", &self.xor_key)
      .field("data_bytes_len", &self.data_bytes.as_ref().map(|b| b.len()))
      .finish()
  }
}

/// A thread-safe metadata value that can be transferred across thread boundaries.
///
/// Used by async tasks to hold scan results before converting to N-API objects.
#[derive(Debug, Clone, PartialEq)]
pub enum MetaValueData {
  /// An integer metadata value.
  Integer(i64),
  /// A floating-point metadata value.
  Float(f64),
  /// A string metadata value.
  String(String),
  /// A boolean metadata value.
  Bool(bool),
}

impl From<MetaValue<'_>> for MetaValueData {
  fn from(value: MetaValue<'_>) -> Self {
    match value {
      MetaValue::Integer(i) => Self::Integer(i),
      MetaValue::Float(f) => Self::Float(f),
      MetaValue::String(s) => Self::String(s.to_string()),
      MetaValue::Bool(b) => Self::Bool(b),
      // Metadata strings with invalid UTF-8 arrive as raw bytes. Decode them
      // lossily instead of replacing the whole value with a placeholder.
      MetaValue::Bytes(b) => Self::String(String::from_utf8_lossy(b).into_owned()),
    }
  }
}

/// A thread-safe representation of a rule match that can cross thread boundaries.
///
/// Unlike `RuleMatch`, this struct contains no N-API references, making it `Send + Sync`.
/// It is used as an intermediate type in async scanning tasks.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleMatchData {
  /// The identifier of the rule that matched.
  pub rule_identifier: String,
  /// The namespace of the rule that matched.
  pub namespace: String,
  /// The metadata associated with the rule, as key-value pairs.
  pub meta: Vec<(String, MetaValueData)>,
  /// The tags associated with the rule that matched.
  pub tags: Vec<String>,
  /// The matches found by the rule.
  pub matches: Vec<MatchData>,
}

/// Represents a matching rule found during scanning.
///
/// Contains the rule's metadata, tags, and all pattern matches.
#[napi(object)]
pub struct RuleMatch<'a> {
  /// The identifier of the rule that matched.
  pub rule_identifier: String,
  /// The namespace of the rule that matched.
  pub namespace: String,
  /// The metadata associated with the rule that matched.
  pub meta: Object<'a>,
  /// The tags associated with the rule that matched.
  pub tags: Vec<String>,
  /// The matches found by the rule.
  pub matches: Vec<MatchData>,
}

/// Options for configuring the YARA compiler.
///
/// These options control various aspects of rule compilation including
/// module handling, optimization, and feature flags.
#[napi(object)]
pub struct CompilerOptions<'a> {
  /// The namespace where the YARA rules should be compiled.
  pub namespace: Option<String>,
  /// Defines global variables for the YARA rules.
  pub define_variables: Option<Object<'a>>,
  /// A list of module names to ignore during compilation.
  pub ignore_modules: Option<Vec<String>>,
  /// A list of banned modules that cannot be used in the YARA rules.
  pub banned_modules: Option<Vec<BannedModule>>,
  /// A list of features to enable for the YARA rules.
  pub features: Option<Vec<String>>,
  /// Whether to use relaxed regular expression syntax.
  pub relaxed_re_syntax: Option<bool>,
  /// Whether to optimize conditions in the YARA rules.
  pub condition_optimization: Option<bool>,
  /// Whether to raise an error on slow patterns.
  pub error_on_slow_pattern: Option<bool>,
  /// Whether to raise an error on slow loops.
  pub error_on_slow_loop: Option<bool>,
  /// Whether to skip rules that fail to compile instead of failing the whole
  /// compilation.
  ///
  /// When `true`, a rule that fails to compile is skipped and the remaining
  /// rules are compiled. The skipped rules, along with the reason, are
  /// reported by
  /// [`YaraX::get_ignored_rules`](crate::YaraX::get_ignored_rules). Errors
  /// that can't be attributed to a single skipped rule (syntax errors,
  /// invalid UTF-8, banned or unknown module imports, include failures) are
  /// reported by
  /// [`YaraX::get_compilation_errors`](crate::YaraX::get_compilation_errors)
  /// instead of aborting the compilation. When `false` (the default), any
  /// rule that fails to compile aborts the compilation with an error.
  pub ignore_invalid_rules: Option<bool>,
  /// Maximum number of warnings the compiler will report.
  ///
  /// When set, only the first `n` warnings are emitted; additional warnings
  /// are dropped. Useful for taming noisy rule corpora, particularly when
  /// the compiler warns on single-byte patterns and duplicate pattern values.
  pub max_warnings: Option<u32>,
  /// Warning codes to disable during compilation.
  ///
  /// Each entry must be a valid YARA-X warning code (e.g. `"slow_pattern"`,
  /// `"duplicate_pattern_value"`, `"potentially_slow_loop"`). An invalid
  /// code produces a compilation error.
  pub disable_warnings: Option<Vec<String>>,
  /// Whether to enable or disable all compiler warnings.
  ///
  /// `true` (the default) leaves all warning types enabled. `false` silences
  /// every warning. Individual codes in `disable_warnings` are applied after
  /// this flag, so an explicitly disabled code stays off even when this is
  /// `true`.
  pub enable_all_warnings: Option<bool>,
  /// A list of directories where the compiler should look for included files.
  pub include_directories: Option<Vec<String>>,
  /// Whether to enable include statements in YARA rules.
  pub enable_includes: Option<bool>,
}

/// A rule that was skipped during compilation.
///
/// Populated whenever rules were skipped: because compilation was performed
/// with `ignore_invalid_rules: true` and some rules failed to compile, or
/// because rules depend on an ignored module (see
/// [`CompilerOptions::ignore_modules`](CompilerOptions::ignore_modules)) or
/// on a rule that was itself skipped. See
/// [`CompilerOptions::ignore_invalid_rules`](CompilerOptions::ignore_invalid_rules).
#[napi(object)]
#[derive(Clone, Debug, PartialEq)]
pub struct IgnoredRule {
  /// The identifier of the ignored rule.
  pub name: String,
  /// Why the rule was ignored: `"ignored_module"`, `"ignored_rule"`, or
  /// `"compile_error"`.
  pub reason: String,
  /// Details depending on the reason: the name of the ignored module, the name
  /// of the ignored rule this one depends on, or the compilation error message.
  pub detail: Option<String>,
}

/// Represents a module that is banned from being used in YARA rules.
///
/// When a banned module is encountered, compilation will fail with the
/// specified error message.
#[napi(object)]
#[derive(Debug, Clone, PartialEq)]
pub struct BannedModule {
  /// The name of the banned module.
  pub name: String,
  /// The title of the error message if the module is used.
  pub error_title: String,
  /// The error message if the module is used.
  pub error_message: String,
}

/// A warning generated by the YARA compiler.
///
/// Warnings indicate potential issues that don't prevent compilation
/// but may indicate problems with the rules.
#[napi(object)]
#[derive(Clone, Debug, PartialEq)]
pub struct CompilerWarning {
  /// The code of the warning.
  pub code: String,
  /// The message of the warning.
  pub message: String,
  /// The source of the warning, if available.
  pub source: Option<String>,
  /// The line number where the warning occurred, if available.
  pub line: Option<u32>,
  /// The column number where the warning occurred, if available.
  pub column: Option<u32>,
}

/// An error generated by the YARA compiler.
///
/// Errors prevent successful compilation and must be resolved before
/// the rules can be used.
#[napi(object)]
#[derive(Clone, Debug, PartialEq)]
pub struct CompilerError {
  /// The code of the error.
  pub code: String,
  /// The message of the error.
  pub message: String,
  /// The source of the error, if available.
  pub source: Option<String>,
  /// The line number where the error occurred, if available.
  pub line: Option<u32>,
  /// The column number where the error occurred, if available.
  pub column: Option<u32>,
}

/// The result of compiling YARA rules.
///
/// Contains any warnings or errors generated during the compilation process.
/// If errors are present, the compilation failed.
#[napi(object)]
#[derive(Clone, Debug, PartialEq)]
pub struct CompileResult {
  /// Any warnings generated during the compilation process.
  pub warnings: Vec<CompilerWarning>,
  /// Any errors generated during the compilation process.
  pub errors: Vec<CompilerError>,
}
