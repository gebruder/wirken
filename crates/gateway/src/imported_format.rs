//! The export format, as observed, and a streaming parse of it.
//!
//! # The format is not a contract
//!
//! These structs describe what a real archive contained, verified by
//! extracting its structure locally. They are not a published
//! interface and nothing upstream promises they will hold. So no
//! struct denies unknown fields: a field added upstream is carried
//! past silently rather than turning an unremarkable addition into a
//! failed import.
//!
//! What is required is only what a record cannot be stored without.
//! A conversation and a message each need their uuid, because it is
//! half the natural key. Everything else defaults, so a field that
//! disappears upstream costs its column rather than the record.
//!
//! # Two kinds of failure, and only one of them is skippable
//!
//! A **schema failure** is an element that parsed as JSON but does not
//! fit these structs. It is skipped, logged by identifier, and the run
//! continues, which is what keeps one odd conversation from costing an
//! entire archive.
//!
//! A **syntax failure** is JSON the parser cannot read. It ends the
//! stream, because there is no way to find where the next element
//! begins without understanding the one that failed. Pretending
//! otherwise would mean guessing at offsets inside attacker-influenced
//! bytes.
//!
//! The distinction is why each element is first taken as a raw
//! fragment and only then fitted to a struct: the sequence stays
//! readable even when an element does not fit.
//!
//! # Byte fidelity
//!
//! A message's content array is captured as raw JSON text, not parsed
//! into a value and re-serialized. Round-tripping through a value type
//! would reorder object keys and normalize whitespace, which is a
//! mutation of a record the design stores exactly as it arrived. The
//! blocks are a union whose tool-use entries carry an input object
//! keyed by whatever parameters the invoked tool took, so there is no
//! typed shape to decompose them into and no reason to try.

use std::io::Read;

use serde::Deserialize;
use serde::de::{DeserializeSeed, Deserializer, SeqAccess, Visitor};
use serde_json::value::RawValue;

/// The account an archive was exported from. Its uuid is the source
/// account label every imported row carries.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct ExportAccount {
    #[serde(default)]
    pub uuid: String,
}

/// One attachment on a message. `extracted_content` is message
/// content that happened to arrive as a file.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct ExportAttachment {
    #[serde(default)]
    pub file_name: String,
    #[serde(default)]
    pub file_size: Option<i64>,
    #[serde(default)]
    pub file_type: String,
    #[serde(default)]
    pub extracted_content: String,
}

/// A file listed on a message. Names only; this list carries no body,
/// which is what separates it from an attachment.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct ExportFile {
    #[serde(default)]
    pub file_name: String,
}

/// One message. `content` is kept as raw JSON so it is stored exactly
/// as it arrived.
#[derive(Debug, Deserialize)]
pub struct ExportMessage {
    pub uuid: String,
    #[serde(default)]
    pub sender: String,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
    #[serde(default)]
    pub attachments: Vec<ExportAttachment>,
    #[serde(default)]
    pub files: Vec<ExportFile>,
    /// The structured content array, verbatim. `None` when the message
    /// carried none.
    #[serde(default)]
    pub content: Option<Box<RawValue>>,
}

impl ExportMessage {
    /// The content array as stored: its own JSON text, or an empty
    /// array when the message carried none.
    pub fn content_json(&self) -> &str {
        self.content.as_ref().map(|c| c.get()).unwrap_or("[]")
    }
}

/// One conversation and its messages.
#[derive(Debug, Deserialize)]
pub struct ExportConversation {
    pub uuid: String,
    /// The title. Empty is normal: real archives carry untitled
    /// conversations, so a view falls back to the uuid rather than
    /// treating this as missing.
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
    #[serde(default)]
    pub account: ExportAccount,
    #[serde(default)]
    pub chat_messages: Vec<ExportMessage>,
}

/// A project's creator, narrowed to the identifier.
///
/// The archive carries a `full_name` here. It is deliberately not a
/// field: a name is third-party personal data, it is the category
/// `users.json` is excluded for, and nothing in viewing or searching a
/// project needs it. Absent from the struct, it cannot reach the
/// store, so the exclusion is a property of the type rather than a
/// rule someone has to remember at the insert site.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct ExportCreator {
    #[serde(default)]
    pub uuid: String,
}

/// One document inside a project. Its `content` is among the largest
/// text values an archive carries and is content for every purpose
/// that word has here: gating, sensitivity, and rendering.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct ExportProjectDoc {
    pub uuid: String,
    #[serde(default)]
    pub filename: String,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub created_at: String,
}

/// One project and its documents.
#[derive(Debug, Deserialize)]
pub struct ExportProject {
    pub uuid: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub prompt_template: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
    #[serde(default)]
    pub is_private: bool,
    #[serde(default)]
    pub is_starter_project: bool,
    #[serde(default)]
    pub creator: ExportCreator,
    #[serde(default)]
    pub docs: Vec<ExportProjectDoc>,
}

/// What happened to one element of the projects array.
#[derive(Debug)]
pub enum ParsedProject {
    Ok(Box<ExportProject>),
    Skipped {
        index: usize,
        uuid: Option<String>,
        reason: String,
    },
}

/// What happened to one element of the conversations array.
#[derive(Debug)]
pub enum ParsedConversation {
    /// It fitted the structs.
    Ok(Box<ExportConversation>),
    /// It parsed as JSON but did not fit. Carries the uuid when one
    /// could be recovered, so the skip is logged against an
    /// identifier rather than a position, and the position otherwise.
    Skipped {
        index: usize,
        uuid: Option<String>,
        reason: String,
    },
}

/// Just enough of a conversation to name one that did not fit.
#[derive(Deserialize)]
struct UuidOnly {
    uuid: Option<String>,
}

/// Stream a conversations array, handing each element to `on_item`.
///
/// Bounded memory: one element is resident at a time, so an archive
/// whose conversation file dwarfs available memory still imports.
///
/// Returns the number of elements seen. An error means the stream
/// ended on JSON the parser could not read, and elements already
/// handed to `on_item` stand.
pub fn stream_conversations<R, F>(reader: R, mut on_item: F) -> Result<usize, serde_json::Error>
where
    R: Read,
    F: FnMut(ParsedConversation),
{
    stream_array::<ExportConversation, _, _>(reader, |index, parsed| {
        on_item(match parsed {
            Ok(c) => ParsedConversation::Ok(Box::new(c)),
            Err((uuid, reason)) => ParsedConversation::Skipped {
                index,
                uuid,
                reason,
            },
        })
    })
}

/// Stream a projects array. Same shape and the same two kinds of
/// failure as conversations; projects inherit the behaviour rather
/// than restating it.
pub fn stream_projects<R, F>(reader: R, mut on_item: F) -> Result<usize, serde_json::Error>
where
    R: Read,
    F: FnMut(ParsedProject),
{
    stream_array::<ExportProject, _, _>(reader, |index, parsed| {
        on_item(match parsed {
            Ok(p) => ParsedProject::Ok(Box::new(p)),
            Err((uuid, reason)) => ParsedProject::Skipped {
                index,
                uuid,
                reason,
            },
        })
    })
}

/// The streaming core. Each element is taken as a raw fragment before
/// anything tries to fit it to `T`, which is what keeps a schema
/// failure from ending the sequence.
fn stream_array<T, R, F>(reader: R, on_item: F) -> Result<usize, serde_json::Error>
where
    T: serde::de::DeserializeOwned,
    R: Read,
    F: FnMut(usize, Result<T, (Option<String>, String)>),
{
    let mut de = serde_json::Deserializer::from_reader(reader);
    let seed = ElementSeq {
        on_item,
        seen: 0,
        index: 0,
        _element: std::marker::PhantomData::<T>,
    };
    seed.deserialize(&mut de)
}

struct ElementSeq<T, F> {
    on_item: F,
    seen: usize,
    index: usize,
    _element: std::marker::PhantomData<T>,
}

impl<'de, T, F> DeserializeSeed<'de> for ElementSeq<T, F>
where
    T: serde::de::DeserializeOwned,
    F: FnMut(usize, Result<T, (Option<String>, String)>),
{
    type Value = usize;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}

impl<'de, T, F> Visitor<'de> for ElementSeq<T, F>
where
    T: serde::de::DeserializeOwned,
    F: FnMut(usize, Result<T, (Option<String>, String)>),
{
    type Value = usize;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("an array of export records")
    }

    fn visit_seq<A>(mut self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        // Each element is taken as a raw fragment first. That is what
        // keeps a schema failure from ending the sequence: the parser
        // has already found this element's bounds before anything
        // tries to fit it to a struct.
        while let Some(raw) = seq.next_element::<Box<RawValue>>()? {
            let index = self.index;
            self.index += 1;
            self.seen += 1;
            match serde_json::from_str::<T>(raw.get()) {
                Ok(element) => (self.on_item)(index, Ok(element)),
                Err(err) => {
                    let uuid = serde_json::from_str::<UuidOnly>(raw.get())
                        .ok()
                        .and_then(|u| u.uuid);
                    (self.on_item)(index, Err((uuid, err.to_string())));
                }
            }
        }
        Ok(self.seen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(json: &str) -> (Vec<ParsedConversation>, Result<usize, String>) {
        let mut items = Vec::new();
        let result = stream_conversations(json.as_bytes(), |item| items.push(item))
            .map_err(|e| e.to_string());
        (items, result)
    }

    #[test]
    fn an_empty_array_yields_nothing() {
        let (items, result) = collect("[]");
        assert!(items.is_empty());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn unknown_fields_are_carried_past_rather_than_refused() {
        // A field nobody has seen before must not cost the record.
        let json = r#"[{"uuid":"c1","name":"t","a_field_from_the_future":{"x":[1,2]}}]"#;
        let (items, result) = collect(json);
        assert_eq!(result.unwrap(), 1);
        match &items[0] {
            ParsedConversation::Ok(c) => assert_eq!(c.uuid, "c1"),
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_optional_field_costs_its_column_not_the_record() {
        let json = r#"[{"uuid":"c1"}]"#;
        let (items, _) = collect(json);
        match &items[0] {
            ParsedConversation::Ok(c) => {
                assert_eq!(c.uuid, "c1");
                assert_eq!(c.name, "");
                assert_eq!(c.summary, "");
                assert_eq!(c.created_at, "");
                assert!(c.chat_messages.is_empty());
                assert_eq!(c.account.uuid, "");
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn a_schema_failure_is_skipped_by_identifier_and_the_run_continues() {
        // The middle element has a uuid of the wrong type. It parses as
        // JSON and does not fit, which is the skippable case.
        let json = r#"[
            {"uuid":"c1"},
            {"uuid":{"not":"a string"}},
            {"uuid":"c3"}
        ]"#;
        let (items, result) = collect(json);
        assert_eq!(result.unwrap(), 3, "every element was seen");
        assert!(matches!(&items[0], ParsedConversation::Ok(c) if c.uuid == "c1"));
        assert!(matches!(&items[2], ParsedConversation::Ok(c) if c.uuid == "c3"));
        match &items[1] {
            ParsedConversation::Skipped { index, uuid, .. } => {
                assert_eq!(*index, 1);
                // The uuid was not a string, so there is no identifier
                // to name and the position stands in for it.
                assert_eq!(*uuid, None);
            }
            other => panic!("expected Skipped, got {other:?}"),
        }
    }

    #[test]
    fn a_skip_names_the_uuid_when_one_can_be_recovered() {
        // Recoverable uuid, unusable elsewhere: chat_messages is the
        // wrong type, so the record does not fit but is nameable.
        let json = r#"[{"uuid":"c9","chat_messages":"not an array"}]"#;
        let (items, _) = collect(json);
        match &items[0] {
            ParsedConversation::Skipped { uuid, reason, .. } => {
                assert_eq!(uuid.as_deref(), Some("c9"));
                assert!(!reason.is_empty());
            }
            other => panic!("expected Skipped, got {other:?}"),
        }
    }

    #[test]
    fn a_conversation_with_no_uuid_is_skipped_by_position() {
        let json = r#"[{"name":"nameless"}]"#;
        let (items, _) = collect(json);
        match &items[0] {
            ParsedConversation::Skipped { index, uuid, .. } => {
                assert_eq!(*index, 0);
                assert_eq!(*uuid, None);
            }
            other => panic!("expected Skipped, got {other:?}"),
        }
    }

    #[test]
    fn a_syntax_failure_ends_the_stream_and_keeps_what_came_before() {
        let json = r#"[{"uuid":"c1"}, {"uuid": }]"#;
        let (items, result) = collect(json);
        assert!(result.is_err(), "unreadable JSON must not be papered over");
        assert_eq!(items.len(), 1, "the readable element stands");
        assert!(matches!(&items[0], ParsedConversation::Ok(c) if c.uuid == "c1"));
    }

    #[test]
    fn a_content_array_is_stored_as_the_bytes_it_arrived_as() {
        // Key order and spacing are preserved. A round trip through a
        // value type would sort these keys and drop the spacing.
        let content = r#"[{"z":1,"a":2,"nested":{"y":null,"b":[1, 2]}}]"#;
        let json =
            format!(r#"[{{"uuid":"c1","chat_messages":[{{"uuid":"m1","content":{content}}}]}}]"#);
        let (items, _) = collect(&json);
        match &items[0] {
            ParsedConversation::Ok(c) => {
                assert_eq!(c.chat_messages[0].content_json(), content);
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn a_message_with_no_content_reads_as_an_empty_array() {
        let json = r#"[{"uuid":"c1","chat_messages":[{"uuid":"m1"}]}]"#;
        let (items, _) = collect(json);
        match &items[0] {
            ParsedConversation::Ok(c) => {
                assert_eq!(c.chat_messages[0].content_json(), "[]");
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn always_null_and_constant_fields_from_the_real_archive_parse() {
        // Shapes the extraction found and this parse must not choke
        // on: block fields that are null in every record, an
        // attachment size of zero, an empty title, and an empty
        // ingestion_date carried inside the verbatim content.
        let json = r#"[{
            "uuid":"c1",
            "name":"",
            "summary":"",
            "account":{"uuid":"acct-1"},
            "chat_messages":[{
                "uuid":"m1",
                "sender":"human",
                "text":"",
                "attachments":[{"file_name":"","file_size":0,"file_type":"","extracted_content":""}],
                "files":[{"file_name":"f"}],
                "content":[{"type":"tool_use","flags":null,"approval_key":null,
                            "approval_options":null,"context":null,
                            "content":[{"type":"knowledge","mime_type":null,
                                        "ingestion_date":"","start":0}]}]
            }]
        }]"#;
        let (items, result) = collect(json);
        assert_eq!(result.unwrap(), 1);
        match &items[0] {
            ParsedConversation::Ok(c) => {
                assert_eq!(c.name, "");
                let m = &c.chat_messages[0];
                assert_eq!(m.attachments[0].file_size, Some(0));
                assert_eq!(m.files[0].file_name, "f");
                assert!(m.content_json().contains("\"flags\":null"));
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    /// The committed test corpus, built to the shapes a real archive
    /// was verified to contain. It is the fixture every later slice
    /// parses, so the shapes stay in one place rather than being
    /// re-invented inline per test.
    const CORPUS: &str = include_str!("../tests/fixtures/synthetic-export/conversations.json");

    #[test]
    fn the_corpus_parses_with_the_shapes_it_was_built_to_exercise() {
        let (items, result) = collect(CORPUS);
        let seen = result.expect("the corpus is readable JSON throughout");
        assert_eq!(seen, items.len());

        let ok: Vec<_> = items
            .iter()
            .filter_map(|i| match i {
                ParsedConversation::Ok(c) => Some(c),
                _ => None,
            })
            .collect();
        let skipped: Vec<_> = items
            .iter()
            .filter_map(|i| match i {
                ParsedConversation::Skipped { uuid, index, .. } => Some((*index, uuid.clone())),
                _ => None,
            })
            .collect();

        // Two records deliberately do not fit: one nameable, one not.
        assert_eq!(skipped.len(), 2, "{skipped:?}");
        assert!(
            skipped
                .iter()
                .any(|(_, u)| u.as_deref() == Some("44444444-4444-4444-8444-444444444444")),
            "the nameable skip is logged by uuid: {skipped:?}"
        );
        assert!(
            skipped.iter().any(|(_, u)| u.is_none()),
            "the record with no uuid is skipped by position: {skipped:?}"
        );

        // Every conversation that fitted carries the same account.
        assert!(
            ok.iter()
                .all(|c| c.account.uuid == "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
        );

        // An empty title is a real shape, not a missing field.
        assert!(ok.iter().any(|c| c.name.is_empty()));

        // A field added upstream costs its column, not the record.
        assert!(
            ok.iter()
                .any(|c| c.uuid == "66666666-6666-4666-8666-666666666666"),
            "the record carrying an unknown field still fitted"
        );

        // Attachment text is message content, including a zero-sized one.
        let sizes: Vec<_> = ok
            .iter()
            .flat_map(|c| &c.chat_messages)
            .flat_map(|m| &m.attachments)
            .map(|a| a.file_size)
            .collect();
        assert!(sizes.contains(&Some(0)), "{sizes:?}");
        assert!(
            ok.iter()
                .flat_map(|c| &c.chat_messages)
                .flat_map(|m| &m.attachments)
                .any(|a| !a.extracted_content.is_empty())
        );

        // Both senders, and the block types the extraction observed.
        let senders: std::collections::BTreeSet<_> = ok
            .iter()
            .flat_map(|c| &c.chat_messages)
            .map(|m| m.sender.as_str())
            .collect();
        assert!(senders.contains("human") && senders.contains("assistant"));
        let blocks = ok
            .iter()
            .flat_map(|c| &c.chat_messages)
            .map(|m| m.content_json())
            .collect::<Vec<_>>()
            .join("");
        for kind in [
            "text",
            "thinking",
            "token_budget",
            "tool_use",
            "tool_result",
        ] {
            assert!(blocks.contains(&format!("\"{kind}\"")), "block type {kind}");
        }

        // Always-null and constant fields survive into stored content.
        //
        // Asserted with the spacing the corpus file uses, not a
        // compact form. That spacing surviving the round trip is the
        // byte-fidelity property visible here: a content array
        // normalized through a value type would arrive as
        // `"flags":null` and fail these.
        for shape in [
            "\"flags\": null",
            "\"approval_key\": null",
            "\"context\": null",
            "\"mime_type\": null",
            "\"subtitles\": null",
            "\"ingestion_date\": \"\"",
            "\"start\": 0",
        ] {
            assert!(blocks.contains(shape), "missing shape {shape}");
        }
    }

    #[test]
    fn corpus_markup_and_unicode_are_stored_unrewritten() {
        // The renderer encodes; the import stores what arrived. A test
        // that passed because the import stripped the markup would be
        // asserting the wrong control.
        let (items, _) = collect(CORPUS);
        let hit = items
            .iter()
            .filter_map(|i| match i {
                ParsedConversation::Ok(c) => Some(c),
                _ => None,
            })
            .flat_map(|c| &c.chat_messages)
            .find(|m| m.text.contains("<script>"))
            .expect("the markup message is in the corpus");
        assert!(hit.text.contains("<script>alert('x')</script>"));
        assert!(hit.text.contains("日本語"));
        assert!(hit.text.contains('🙂'));
        assert!(hit.text.contains('\\'));
    }

    const PROJECT_CORPUS: &str = include_str!("../tests/fixtures/synthetic-export/projects.json");

    fn collect_projects(json: &str) -> (Vec<ParsedProject>, Result<usize, String>) {
        let mut items = Vec::new();
        let result =
            stream_projects(json.as_bytes(), |item| items.push(item)).map_err(|e| e.to_string());
        (items, result)
    }

    #[test]
    fn the_project_corpus_parses_and_skips_the_record_built_not_to_fit() {
        let (items, result) = collect_projects(PROJECT_CORPUS);
        let seen = result.expect("the corpus is readable JSON throughout");
        assert_eq!(seen, items.len());

        let ok: Vec<_> = items
            .iter()
            .filter_map(|i| match i {
                ParsedProject::Ok(p) => Some(p),
                _ => None,
            })
            .collect();
        let skipped: Vec<_> = items
            .iter()
            .filter_map(|i| match i {
                ParsedProject::Skipped { uuid, .. } => Some(uuid.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(skipped.len(), 1, "{skipped:?}");
        assert_eq!(
            skipped[0].as_deref(),
            Some("aaaa4444-4444-4444-8444-444444444444"),
            "the skip is named by uuid"
        );

        // Both booleans, an empty description, a project with no
        // documents, and a document with empty content.
        assert!(ok.iter().any(|p| p.is_starter_project));
        assert!(ok.iter().any(|p| !p.is_starter_project));
        assert!(ok.iter().any(|p| p.description.is_empty()));
        assert!(ok.iter().any(|p| p.docs.is_empty()));
        assert!(
            ok.iter()
                .flat_map(|p| &p.docs)
                .any(|d| d.content.is_empty())
        );

        // A field added upstream costs its column, not the record.
        assert!(
            ok.iter()
                .any(|p| p.uuid == "aaaa3333-3333-4333-8333-333333333333")
        );
    }

    #[test]
    fn a_creator_name_is_not_a_field_the_parser_has() {
        // The corpus carries the name. Nothing the parser produces can
        // hold it, because the struct has no place to put it.
        assert!(PROJECT_CORPUS.contains("A Person Whose Name Must Not Be Stored"));
        let (items, _) = collect_projects(PROJECT_CORPUS);
        for item in &items {
            let rendered = format!("{item:?}");
            assert!(
                !rendered.contains("A Person"),
                "a parsed project carries the name: {rendered}"
            );
        }
    }

    #[test]
    fn project_markup_is_kept_as_subject_matter() {
        let (items, _) = collect_projects(PROJECT_CORPUS);
        let p = items
            .iter()
            .filter_map(|i| match i {
                ParsedProject::Ok(p) => Some(p),
                _ => None,
            })
            .find(|p| p.description.contains("<script>"))
            .expect("the markup project is in the corpus");
        assert!(p.description.contains("<script>alert('project')</script>"));
        assert!(p.docs[0].content.contains("onerror=alert('doc')"));
        assert!(p.docs[0].content.contains("日本語"));
    }

    #[test]
    fn a_top_level_value_that_is_not_an_array_is_an_error() {
        let (items, result) = collect(r#"{"uuid":"c1"}"#);
        assert!(result.is_err());
        assert!(items.is_empty());
    }
}
