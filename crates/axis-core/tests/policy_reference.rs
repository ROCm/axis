// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Keeps `docs/policy-reference.md` in step with the policy model.
//!
//! The list of policy fields is read from the model, not copied here. Every
//! policy struct rejects unknown keys, and serde's error for one names the keys
//! it expected, so a probe key that cannot exist, placed at a path, returns the
//! field names of the struct at that path. Following those names down gives
//! every key path of the model. Enum values come the same way from the
//! `unknown variant` error, and defaults come from parsing a small fixture and
//! serializing the policy again.
//!
//! The page is checked against that model:
//!
//! - Rows: each section has one field table, every documented path has one row
//!   in it, and no row names a path the model lacks.
//! - Defaults: each default cell equals the default the code produces.
//! - Values: the code spans in a type and values cell are exactly the values of
//!   an enum field, and none for any other field. The row of an enum field
//!   mentions each alias that the type accepts, and every code span in a
//!   sentence of its meaning that uses the word "alias" is a value or an alias
//!   that the type accepts.
//!
//! The test does not check type descriptions beyond enum values, or meaning
//! text.
//!
//! Discovery cannot see the children of a map-valued field. It stops with an
//! error on such a field instead of skipping it.
//!
//! Row convention: a field has a row when it is a scalar, a list, or a mapping
//! that can be left out (`Option`). A mapping that is always present (a plain
//! struct such as `filesystem`) has no row of its own, only its fields do. A
//! list of mappings has a row for the list (`network.policies`) and its
//! children are written `parent[].child`.

use axis_core::policy::Policy;
use serde_yaml::{Mapping, Value};
use std::collections::BTreeSet;
use std::path::PathBuf;

const DOC_PATH: &str = "docs/policy-reference.md";

const FIELD_HEADER: [&str; 4] = ["Field", "Type and values", "Default", "Meaning"];

/// Top-level keys that hold one value instead of a section of fields.
const SCALAR_KEYS: [&str; 2] = ["version", "name"];

/// Fewer paths or enum fields than these mean that discovery stopped early,
/// not that the model shrank.
const MIN_PATHS: usize = 60;
const MIN_ENUM_FIELDS: usize = 8;

/// A small policy that sets every section, every optional mapping and every list
/// entry, with only the keys that must be set. Defaults are read from it, so a
/// new section, optional mapping or list needs an entry here. It is parsed
/// without `validate`, so it need not be a launchable policy.
const FIXTURE: &str = r"
version: 1
name: reference
runtime: {}
filesystem: {}
process: {}
network:
  policies:
    - name: group
      endpoints:
        - host: example.com
          port: 443
          rules:
            - allow:
                method: GET
                path: /
      binaries:
        - path: /usr/bin/example
inference:
  routes:
    - name: route
  scheduling: {}
  token_budget:
    max_tokens_per_hour: 1
gpu: {}
ssh:
  allowed_keys:
    - name: key
      private_key: /key
amd:
  apex_memory_policy: {}
";

#[test]
fn discovery_reaches_every_section_of_the_model() {
    // The checks are inside discover_model, so that every test below runs them.
    discover_model();
}

#[test]
fn doc_tables_have_the_expected_shape() {
    let model = discover_model();
    let doc = parse_doc(&read_doc(), &section_names(&model));
    assert_no_problems(&doc.problems);
}

#[test]
fn every_documented_field_has_one_row() {
    let model = discover_model();
    let doc = parse_doc(&read_doc(), &section_names(&model));
    let mut problems = Vec::new();

    for field in model.iter().filter(|field| field.documented) {
        let path = field.path();
        let rows = doc.rows(&path).count();
        if rows == 0 {
            problems.push(format!(
                "`{path}` has no row in the field table of `## {}`; document it in {DOC_PATH}",
                field.section()
            ));
        } else if rows > 1 {
            problems.push(format!("`{path}` has {rows} rows; keep one in {DOC_PATH}"));
        }
    }
    assert_no_problems(&problems);
}

#[test]
fn every_row_names_a_documented_field() {
    let model = discover_model();
    let doc = parse_doc(&read_doc(), &section_names(&model));
    let documented: BTreeSet<String> = model
        .iter()
        .filter(|field| field.documented)
        .map(Field::path)
        .collect();
    let mut problems = Vec::new();

    for row in &doc.rows {
        if !documented.contains(&row.path) {
            problems.push(format!(
                "the field table of `## {}` has a row for `{}`, which is not a documented policy field; remove or correct the row in {DOC_PATH}",
                row.section, row.path
            ));
        } else if row.path.split(['.', '[']).next() != Some(row.section.as_str()) {
            problems.push(format!(
                "`{}` is in the field table of `## {}`; move the row to its own section in {DOC_PATH}",
                row.path, row.section
            ));
        }
    }
    assert_no_problems(&problems);
}

#[test]
fn documented_defaults_match_the_model() {
    let model = discover_model();
    let doc = parse_doc(&read_doc(), &section_names(&model));
    let mut problems = Vec::new();

    for field in model.iter().filter(|field| field.documented) {
        let path = field.path();
        // A missing or repeated row is reported by its own test.
        let Some(row) = doc.rows(&path).next() else {
            continue;
        };
        let Some(documented) = code_span(&row.cells[2]) else {
            problems.push(format!(
                "the default of `{path}` must be one code span in {DOC_PATH}"
            ));
            continue;
        };
        let actual = code_default(field);
        if documented != actual {
            problems.push(format!(
                "the default of `{path}` is documented as `{documented}`; the model default is `{actual}`. Update the row in {DOC_PATH}"
            ));
        }
    }
    assert_no_problems(&problems);
}

#[test]
fn values_cells_match_the_enum_fields() {
    let model = discover_model();
    let doc = parse_doc(&read_doc(), &section_names(&model));
    let mut problems = Vec::new();

    for field in model.iter().filter(|field| field.documented) {
        let path = field.path();
        let Some(row) = doc.rows(&path).next() else {
            continue;
        };
        let documented: BTreeSet<&str> = code_spans(&row.cells[1]).into_iter().collect();
        let actual: BTreeSet<&str> = field.variants.iter().map(String::as_str).collect();
        if documented != actual {
            problems.push(format!(
                "the type and values cell of `{path}` has the code spans {documented:?}; the model accepts the values {actual:?}. Update the row in {DOC_PATH}"
            ));
        }
        // An alias is not a value of its own, but the row has to mention it.
        for alias in &field.aliases {
            if !row
                .cells
                .iter()
                .any(|cell| code_spans(cell).contains(&alias.as_str()))
            {
                problems.push(format!(
                    "the row of `{path}` does not mention the accepted alias `{alias}`; add it in {DOC_PATH}"
                ));
            }
        }
        // The other way: a code span in a sentence of the meaning that uses the
        // word "alias" must be a value or an alias that the model accepts.
        for sentence in row.cells[3].split(". ").filter(|s| s.contains("alias")) {
            for name in code_spans(sentence) {
                let mut known = field.variants.iter().chain(&field.aliases);
                if !known.any(|known| known == name) {
                    problems.push(format!(
                        "the row of `{path}` mentions `{name}` as an alias, which the model does not accept; correct it in {DOC_PATH}"
                    ));
                }
            }
        }
    }
    assert_no_problems(&problems);
}

fn assert_no_problems(problems: &[String]) {
    assert!(
        problems.is_empty(),
        "{DOC_PATH} is out of step with the policy model:\n- {}",
        problems.join("\n- ")
    );
}

// ---------------------------------------------------------------------------
// The model: key paths, enum values and defaults, read from the code.
// ---------------------------------------------------------------------------

/// One key in a path. `list` means the value is a list of mappings and the
/// path goes on into one entry of it.
#[derive(Clone, Debug)]
struct Step {
    key: String,
    list: bool,
}

struct Field {
    steps: Vec<Step>,
    /// Whether the reference page has a row for this path: every field except
    /// a mapping that is always present.
    documented: bool,
    /// The values of an enum field, as the policy serializes them; empty for
    /// every other field.
    variants: Vec<String>,
    /// Other names that an enum field accepts for one of its values.
    aliases: Vec<String>,
}

impl Field {
    /// A mapping or a list of mappings.
    fn container(steps: Vec<Step>, documented: bool) -> Self {
        Self {
            steps,
            documented,
            variants: Vec::new(),
            aliases: Vec::new(),
        }
    }

    /// The path as the page writes it: `[]` marks each list on the way to the
    /// field, but not a list that is the field.
    fn path(&self) -> String {
        let (last, parents) = self.steps.split_last().expect("a path has a key");
        let mut path = String::new();
        for step in parents {
            path.push_str(&step.key);
            path.push_str(if step.list { "[]." } else { "." });
        }
        path.push_str(&last.key);
        path
    }

    fn section(&self) -> &str {
        &self.steps[0].key
    }
}

fn section_names(model: &[Field]) -> Vec<String> {
    model
        .iter()
        .filter(|field| field.steps.len() == 1)
        .map(|field| field.steps[0].key.clone())
        .collect()
}

/// Reads every key path of `Policy`, and checks that the read worked, so that
/// a change in serde's error text fails here instead of producing a short list.
fn discover_model() -> Vec<Field> {
    let root = listed(parse_error("{__probe: 1}"), "unknown field").expect(
        "probing the policy root did not list its fields; has serde's unknown-field error changed?",
    );
    let mut fields = Vec::new();
    discover_into(&[], &root, &mut fields);

    let paths: Vec<String> = fields.iter().map(Field::path).collect();
    assert!(
        paths.iter().any(|path| path == "version"),
        "discovery did not find `version`"
    );
    assert!(
        fields.len() >= MIN_PATHS,
        "discovery found only {} paths: {paths:?}",
        fields.len()
    );
    for key in &root {
        if SCALAR_KEYS.contains(&key.as_str()) {
            continue;
        }
        assert!(
            fields
                .iter()
                .any(|field| field.steps.len() > 1 && field.steps[0].key == *key),
            "discovery found no fields under the top-level key `{key}`; if it holds one value, add it to SCALAR_KEYS"
        );
    }
    let enums = fields
        .iter()
        .filter(|field| !field.variants.is_empty())
        .count();
    assert!(
        enums >= MIN_ENUM_FIELDS,
        "discovery found only {enums} enum fields; has serde's unknown-variant error changed?"
    );
    fields
}

/// Adds each name under `parent` to `fields`, then follows the ones that are
/// mappings or lists of mappings.
fn discover_into(parent: &[Step], names: &[String], fields: &mut Vec<Field>) {
    for name in names {
        let mut steps = parent.to_vec();
        steps.push(Step {
            key: name.clone(),
            list: false,
        });

        // A mapping: the probe key is refused with the list of its keys.
        if let Some(children) = struct_fields(&steps) {
            // A mapping that is null when left out can be left out, so it has
            // a row. One that is always present does not.
            let documented = match left_out(&steps) {
                LeftOut::Value(Value::Null) => true,
                LeftOut::Value(_) => false,
                // Not serialized when empty: it has a row if it can be null.
                LeftOut::Omitted(policy) => parses_with(&policy, &steps, Value::Null),
                LeftOut::Required => panic!(
                    "the mapping `{}` is required; decide in policy_reference.rs whether it has a row",
                    path_of(&steps)
                ),
            };
            fields.push(Field::container(steps.clone(), documented));
            discover_into(&steps, &children, fields);
            continue;
        }

        // A list of mappings: the same, one entry down.
        steps.last_mut().expect("just pushed").list = true;
        if let Some(children) = struct_fields(&steps) {
            fields.push(Field::container(steps.clone(), true));
            discover_into(&steps, &children, fields);
            continue;
        }

        // Anything else is a leaf. A leaf has to refuse a mapping, or it is
        // a type this discovery does not understand. An empty mapping is the
        // probe: a field whose value is a map of keys to values accepts it,
        // where the probe key above would be refused for its value instead.
        steps.last_mut().expect("just pushed").list = false;
        let refusal = parse_error(&wrap(&steps, "{}")).unwrap_or_default();
        assert!(
            refusal.contains("invalid type") || refusal.contains("unknown variant"),
            "cannot classify `{}`: probing it with an empty mapping gave `{refusal}`",
            path_of(&steps)
        );
        // Likewise a list of mappings; one whose entries accept unknown keys
        // or are maps would hide its fields.
        let mut as_list = steps.clone();
        as_list.last_mut().expect("just pushed").list = true;
        let list_refusal = parse_error(&wrap(&as_list, "{}")).unwrap_or_default();
        assert!(
            list_refusal.contains("invalid type") || list_refusal.contains("unknown variant"),
            "cannot classify `{}`: probing it with a list of empty mappings gave `{list_refusal}`",
            path_of(&steps)
        );
        // An enum rejects a value that is none of its variants.
        let accepted = listed(parse_error(&wrap(&steps, "__probe")), "unknown variant")
            .or_else(|| listed(parse_error(&wrap(&steps, "[__probe]")), "unknown variant"))
            .unwrap_or_default();
        let mut variants = BTreeSet::new();
        let mut aliases = Vec::new();
        for name in accepted {
            let canonical = canonical_variant(&steps, &name);
            if canonical != name {
                aliases.push(name);
            }
            variants.insert(canonical);
        }
        fields.push(Field {
            steps,
            documented: true,
            variants: variants.into_iter().collect(),
            aliases,
        });
    }
}

/// The keys of the mapping at `steps`, if there is one.
fn struct_fields(steps: &[Step]) -> Option<Vec<String>> {
    listed(parse_error(&wrap(steps, "{__probe: 1}")), "unknown field")
}

/// Builds a policy document with `leaf` at `steps`. Probes leave out `version`
/// and `name`: serde reports the probe before it reports a missing key.
fn wrap(steps: &[Step], leaf: &str) -> String {
    let mut yaml = leaf.to_owned();
    for step in steps.iter().rev() {
        let value = if step.list { format!("[{yaml}]") } else { yaml };
        yaml = format!("{{{}: {value}}}", step.key);
    }
    yaml
}

fn parse_error(yaml: &str) -> Option<String> {
    serde_yaml::from_str::<Policy>(yaml)
        .err()
        .map(|error| error.to_string())
}

/// The names in serde's `unknown <what> `__probe`, expected one of `a`, `b``
/// (or `expected `a` or `b``, or `expected `a``). `None` when the error is of
/// another kind.
fn listed(message: Option<String>, what: &str) -> Option<Vec<String>> {
    let message = message?;
    let (_, after) = message.split_once(&format!("{what} `__probe`"))?;
    let (_, names) = after
        .split_once(", expected ")
        .unwrap_or_else(|| panic!("serde's {what} error lists no names: {message}"));
    // Names sit between backticks; the text between them is skipped.
    let names: Vec<String> = names
        .split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect();
    assert!(!names.is_empty(), "no names found in: {message}");
    Some(names)
}

fn path_of(steps: &[Step]) -> String {
    steps
        .iter()
        .map(|step| step.key.as_str())
        .collect::<Vec<_>>()
        .join(".")
}

fn fixture() -> Value {
    serde_yaml::from_str(FIXTURE).expect("the fixture is YAML")
}

/// What the code does when a key is left out of the fixture.
enum LeftOut {
    /// Parsing fails on the missing key.
    Required,
    /// The key has this value in the serialized policy.
    Value(Value),
    /// The serializer omits the key, which it does only for the empty value.
    /// Holds the fixture without the key.
    Omitted(Value),
}

fn left_out(steps: &[Step]) -> LeftOut {
    let path = path_of(steps);
    let (last, parents) = steps.split_last().expect("a path has a key");
    let mut policy = fixture();
    // The parent must be in the fixture, or the default read here would be the
    // default of the parent as a whole, not of the key.
    let parent = parent_mut(&mut policy, parents)
        .and_then(Value::as_mapping_mut)
        .unwrap_or_else(|| {
            panic!(
                "the fixture in policy_reference.rs has no mapping for the parent of `{path}`; add one"
            )
        });
    let removed = parent.remove(last.key.as_str()).is_some();

    let parsed = match serde_yaml::from_value::<Policy>(policy.clone()) {
        Ok(parsed) => parsed,
        Err(error) => {
            assert!(
                removed,
                "the fixture in policy_reference.rs does not parse: {error}"
            );
            assert!(
                error
                    .to_string()
                    .contains(&format!("missing field `{}`", last.key)),
                "leaving out `{path}` failed for another reason: {error}"
            );
            return LeftOut::Required;
        }
    };

    let serialized = serde_yaml::to_value(&parsed).expect("a policy serializes");
    let parent = lookup(&serialized, parents).expect("the parent is in the fixture");
    match parent.get(last.key.as_str()) {
        Some(value) => LeftOut::Value(value.clone()),
        None => LeftOut::Omitted(policy),
    }
}

/// The default of `field` as the page writes it.
fn code_default(field: &Field) -> String {
    match left_out(&field.steps) {
        LeftOut::Required => "required".to_owned(),
        LeftOut::Value(value) => render(&field.path(), &value),
        // The serializer leaves out a key only when it holds the empty value,
        // which is the default if it parses to the same policy. An optional
        // field differs from `[]` and `false` there, and a list accepts `null`,
        // so `none` comes last.
        LeftOut::Omitted(policy) => {
            let unchanged = format!("{:?}", parse(&policy));
            let candidates = [
                (Value::Sequence(Vec::new()), "[]"),
                (Value::Bool(false), "false"),
                (Value::Null, "none"),
            ];
            for (value, rendered) in candidates {
                let mut probe = policy.clone();
                set_path(&mut probe, &field.steps, value);
                if serde_yaml::from_value::<Policy>(probe)
                    .is_ok_and(|parsed| format!("{parsed:?}") == unchanged)
                {
                    return rendered.to_owned();
                }
            }
            panic!(
                "`{}` is not serialized and none of `none`, `[]` and `false` is its default; extend code_default",
                field.path()
            );
        }
    }
}

fn parse(policy: &Value) -> Policy {
    serde_yaml::from_value(policy.clone()).expect("the fixture parses")
}

/// Whether `policy` still parses with `value` at `steps`.
fn parses_with(policy: &Value, steps: &[Step], value: Value) -> bool {
    let mut policy = policy.clone();
    set_path(&mut policy, steps, value);
    serde_yaml::from_value::<Policy>(policy).is_ok()
}

/// The value that `name` stands for, which differs from `name` for an alias.
/// An alias parses but is serialized under the name of its variant.
fn canonical_variant(steps: &[Step], name: &str) -> String {
    let fixture = fixture();
    let (last, parents) = steps.split_last().expect("a path has a key");
    for value in [
        Value::String(name.to_owned()),
        Value::Sequence(vec![Value::String(name.to_owned())]),
    ] {
        let mut policy = fixture.clone();
        set_path(&mut policy, steps, value);
        let Ok(parsed) = serde_yaml::from_value::<Policy>(policy) else {
            continue;
        };
        let serialized = serde_yaml::to_value(&parsed).expect("a policy serializes");
        let stored = lookup(&serialized, parents).and_then(|parent| parent.get(last.key.as_str()));
        match stored {
            Some(Value::String(canonical)) => return canonical.clone(),
            Some(Value::Sequence(items)) if items.len() == 1 => {
                if let Value::String(canonical) = &items[0] {
                    return canonical.clone();
                }
            }
            _ => {}
        }
    }
    panic!(
        "`{}` accepts `{name}` but does not serialize it back; extend canonical_variant",
        path_of(steps)
    );
}

/// A default as the page writes it.
fn render(path: &str, value: &Value) -> String {
    match value {
        Value::Null => "none".to_owned(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => format!("{value:?}"),
        Value::Sequence(items) if items.is_empty() => "[]".to_owned(),
        _ => panic!("the default of `{path}` is a compound value; extend render"),
    }
}

/// The value at `steps`, entering the first entry of each list on the way.
fn lookup<'a>(root: &'a Value, steps: &[Step]) -> Option<&'a Value> {
    let mut node = root;
    for step in steps {
        node = node.get(step.key.as_str())?;
        if step.list {
            node = node.get(0)?;
        }
    }
    Some(node)
}

/// Like `lookup`, for a value that can be changed.
fn parent_mut<'a>(root: &'a mut Value, steps: &[Step]) -> Option<&'a mut Value> {
    let mut node = root;
    for step in steps {
        node = node.get_mut(step.key.as_str())?;
        if step.list {
            node = node.get_mut(0)?;
        }
    }
    Some(node)
}

/// Sets the key at `steps` to `value`, creating the mappings above it. A list
/// on the way must already have an entry in the fixture.
fn set_path(root: &mut Value, steps: &[Step], value: Value) {
    let (last, parents) = steps.split_last().expect("a path has a key");
    let mut node = root;
    for step in parents {
        let mapping = node.as_mapping_mut().expect("parents are mappings");
        let key = Value::from(step.key.as_str());
        if !mapping.contains_key(&key) {
            assert!(
                !step.list,
                "the fixture in policy_reference.rs has no list `{}`; add one",
                step.key
            );
            mapping.insert(key.clone(), Value::Mapping(Mapping::new()));
        }
        node = mapping.get_mut(&key).expect("the key is present");
        if step.list {
            node = node.get_mut(0).unwrap_or_else(|| {
                panic!(
                    "the fixture in policy_reference.rs has an empty list `{}`; add an entry",
                    step.key
                )
            });
        }
    }
    node.as_mapping_mut()
        .expect("parents are mappings")
        .insert(Value::from(last.key.as_str()), value);
}

// ---------------------------------------------------------------------------
// The page: sections, tables and rows.
// ---------------------------------------------------------------------------

struct Row {
    section: String,
    /// The key path from the first cell.
    path: String,
    /// Every cell, the first included.
    cells: Vec<String>,
}

struct Doc {
    /// The rows of every field table.
    rows: Vec<Row>,
    /// Defects in the tables themselves; the checks above read rows only.
    problems: Vec<String>,
}

impl Doc {
    fn rows<'a>(&'a self, path: &'a str) -> impl Iterator<Item = &'a Row> {
        self.rows.iter().filter(move |row| row.path == path)
    }
}

fn read_doc() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(DOC_PATH);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

/// Splits the page at `## ` headings and collects the field table of each
/// section. A top-level key's section must have no other table: the lines of
/// any table without the field header are reported. Headed sections other than
/// the model's top-level keys (the introduction) must not have a field table.
fn parse_doc(text: &str, section_names: &[String]) -> Doc {
    let mut doc = Doc {
        rows: Vec::new(),
        problems: Vec::new(),
    };

    let sections = split_sections(text);
    for name in section_names {
        if !sections.iter().any(|(section, _)| section == name) {
            doc.problems
                .push(format!("{DOC_PATH} has no `## {name}` section"));
        }
    }

    for (section, tables) in sections {
        let field_tables: Vec<Vec<Vec<String>>> = tables
            .iter()
            .map(|lines| lines.iter().map(|line| split_row(line)).collect::<Vec<_>>())
            .filter(|table| table[0] == FIELD_HEADER)
            .collect();
        if !section_names.contains(&section) {
            if !field_tables.is_empty() {
                doc.problems.push(format!(
                    "`## {section}` has a field table but is not a top-level policy key"
                ));
            }
            continue;
        }
        if field_tables.len() != 1 {
            doc.problems.push(format!(
                "`## {section}` must have one field table with the header `| {} |`; found {}",
                FIELD_HEADER.join(" | "),
                field_tables.len()
            ));
        }
        // A table line that is not in the field table is not read as a row, so
        // it is reported. A blank line inside the table starts such a table.
        for table in tables
            .iter()
            .filter(|table| split_row(table[0]) != FIELD_HEADER)
        {
            doc.problems.push(format!(
                "`## {section}` has a table line outside its field table: `{}`; keep every row in the one field table in {DOC_PATH}",
                table[0].trim()
            ));
        }
        for table in &field_tables {
            read_table(&mut doc, &section, table);
        }
    }
    doc
}

/// The tables of each `## ` section, as lines. Fenced code is skipped.
fn split_sections(text: &str) -> Vec<(String, Vec<Vec<&str>>)> {
    let mut sections: Vec<(String, Vec<Vec<&str>>)> = Vec::new();
    let mut in_fence = false;
    let mut in_table = false;
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            in_table = false;
        } else if in_fence {
            continue;
        } else if let Some(name) = line.strip_prefix("## ") {
            sections.push((name.trim().to_owned(), Vec::new()));
            in_table = false;
        } else if line.trim_start().starts_with('|') {
            let Some((_, tables)) = sections.last_mut() else {
                continue;
            };
            match tables.last_mut() {
                Some(table) if in_table => table.push(line),
                _ => tables.push(vec![line]),
            }
            in_table = true;
        } else {
            in_table = false;
        }
    }
    sections
}

/// Splits a table line into trimmed cells. `\|` is a pipe inside a cell.
fn split_row(line: &str) -> Vec<String> {
    let line = line.trim();
    let line = line.strip_prefix('|').unwrap_or(line);
    let line = line.strip_suffix('|').unwrap_or(line);
    let mut cells = vec![String::new()];
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&'|') => {
                chars.next();
                cells.last_mut().expect("one cell at least").push('|');
            }
            '|' => cells.push(String::new()),
            _ => cells.last_mut().expect("one cell at least").push(c),
        }
    }
    cells.iter().map(|cell| cell.trim().to_owned()).collect()
}

/// Checks the separator line and each row of a field table, and keeps the
/// rows.
fn read_table(doc: &mut Doc, section: &str, table: &[Vec<String>]) {
    let width = table[0].len();
    let is_separator = table.get(1).is_some_and(|cells| {
        cells.len() == width
            && cells
                .iter()
                .all(|cell| cell.contains('-') && cell.chars().all(|c| c == '-' || c == ':'))
    });
    if !is_separator {
        doc.problems.push(format!(
            "the field table of `## {section}` has no separator line under its header"
        ));
    }

    for cells in table.iter().skip(2) {
        let shown = cells.first().map_or("", |cell| cell.trim_matches('`'));
        if cells.len() != width {
            doc.problems.push(format!(
                "the row `{shown}` in the field table of `## {section}` has {} cells; expected {width}",
                cells.len()
            ));
            continue;
        }
        let Some(path) = code_span(&cells[0]) else {
            doc.problems.push(format!(
                "the first cell `{shown}` in the field table of `## {section}` must be a key path in one code span"
            ));
            continue;
        };
        doc.rows.push(Row {
            section: section.to_owned(),
            path: path.to_owned(),
            cells: cells.clone(),
        });
    }
}

/// The text of a cell that is exactly one code span.
fn code_span(cell: &str) -> Option<&str> {
    let inner = cell.strip_prefix('`')?.strip_suffix('`')?;
    (!inner.contains('`')).then_some(inner)
}

/// The text of every code span in a cell.
fn code_spans(cell: &str) -> Vec<&str> {
    cell.split('`').skip(1).step_by(2).collect()
}
