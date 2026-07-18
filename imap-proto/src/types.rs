use std::borrow::Cow;
use std::collections::HashMap;
use std::ops::RangeInclusive;

pub mod acls;
pub use acls::*;

fn to_owned_cow<T: ?Sized + ToOwned>(c: Cow<'_, T>) -> Cow<'static, T> {
    Cow::Owned(c.into_owned())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request<'a>(pub Cow<'a, [u8]>, pub Cow<'a, [u8]>);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AttrMacro {
    All,
    Fast,
    Full,
}

#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Response<'a> {
    Capabilities(Vec<Capability<'a>>),
    /// Capabilities successfully enabled by an RFC 5161 ENABLE command.
    Enabled(Vec<Capability<'a>>),
    Continue {
        code: Option<ResponseCode<'a>>,
        information: Option<Cow<'a, str>>,
    },
    Done {
        tag: RequestId,
        status: Status,
        code: Option<ResponseCode<'a>>,
        information: Option<Cow<'a, str>>,
    },
    Data {
        status: Status,
        code: Option<ResponseCode<'a>>,
        information: Option<Cow<'a, str>>,
    },
    Expunge(u32),
    Vanished {
        earlier: bool,
        uids: Vec<std::ops::RangeInclusive<u32>>,
    },
    Fetch(u32, Vec<AttributeValue<'a>>),
    /// An RFC 9586 UIDFETCH response. The leading number is always a UID,
    /// never a mutable message sequence number.
    UidFetch(u32, Vec<AttributeValue<'a>>),
    MailboxData(MailboxDatum<'a>),
    Quota(Quota<'a>),
    QuotaRoot(QuotaRoot<'a>),
    Id(Option<HashMap<Cow<'a, str>, Cow<'a, str>>>),
    Acl(Acl<'a>),
    ListRights(ListRights<'a>),
    MyRights(MyRights<'a>),
}

impl<'a> Response<'a> {
    pub fn from_bytes(buf: &'a [u8]) -> crate::ParseResult<'a> {
        crate::parser::parse_response(buf)
    }

    pub fn into_owned(self) -> Response<'static> {
        match self {
            Response::Capabilities(capabilities) => Response::Capabilities(
                capabilities
                    .into_iter()
                    .map(Capability::into_owned)
                    .collect(),
            ),
            Response::Enabled(capabilities) => Response::Enabled(
                capabilities
                    .into_iter()
                    .map(Capability::into_owned)
                    .collect(),
            ),
            Response::Continue { code, information } => Response::Continue {
                code: code.map(ResponseCode::into_owned),
                information: information.map(to_owned_cow),
            },
            Response::Done {
                tag,
                status,
                code,
                information,
            } => Response::Done {
                tag,
                status,
                code: code.map(ResponseCode::into_owned),
                information: information.map(to_owned_cow),
            },
            Response::Data {
                status,
                code,
                information,
            } => Response::Data {
                status,
                code: code.map(ResponseCode::into_owned),
                information: information.map(to_owned_cow),
            },
            Response::Expunge(seq) => Response::Expunge(seq),
            Response::Vanished { earlier, uids } => Response::Vanished { earlier, uids },
            Response::Fetch(seq, attrs) => Response::Fetch(
                seq,
                attrs.into_iter().map(AttributeValue::into_owned).collect(),
            ),
            Response::UidFetch(uid, attrs) => Response::UidFetch(
                uid,
                attrs.into_iter().map(AttributeValue::into_owned).collect(),
            ),
            Response::MailboxData(datum) => Response::MailboxData(datum.into_owned()),
            Response::Quota(quota) => Response::Quota(quota.into_owned()),
            Response::QuotaRoot(quota_root) => Response::QuotaRoot(quota_root.into_owned()),
            Response::Id(map) => Response::Id(map.map(|m| {
                m.into_iter()
                    .map(|(k, v)| (to_owned_cow(k), to_owned_cow(v)))
                    .collect()
            })),
            Response::Acl(acl_list) => Response::Acl(acl_list.into_owned()),
            Response::ListRights(rights) => Response::ListRights(rights.into_owned()),
            Response::MyRights(rights) => Response::MyRights(rights.into_owned()),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Status {
    Ok,
    No,
    Bad,
    PreAuth,
    Bye,
}

#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ResponseCode<'a> {
    Alert,
    BadCharset(Option<Vec<Cow<'a, str>>>),
    Capabilities(Vec<Capability<'a>>),
    HighestModSeq(u64), // RFC 4551, section 3.1.1
    Parse,
    PermanentFlags(Vec<Cow<'a, str>>),
    ReadOnly,
    ReadWrite,
    TryCreate,
    UidNext(u32),
    UidValidity(u32),
    Unseen(u32),
    AppendUid(u32, Vec<UidSetMember>),
    CopyUid(u32, Vec<UidSetMember>, Vec<UidSetMember>),
    UidNotSticky,
    /// RFC 9586: a sequence-number command was attempted in UIDONLY mode.
    UidRequired,
    /// RFC 9738: command processing stopped at the advertised message limit.
    MessageLimit {
        limit: u32,
        last_uid: Option<u32>,
    },
    MetadataLongEntries(u64), // RFC 5464, section 4.2.1
    MetadataMaxSize(u64),     // RFC 5464, section 4.3
    MetadataTooMany,          // RFC 5464, section 4.3
    MetadataNoPrivate,        // RFC 5464, section 4.3
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UidSetMember {
    UidRange(RangeInclusive<u32>),
    Uid(u32),
}

impl From<RangeInclusive<u32>> for UidSetMember {
    fn from(x: RangeInclusive<u32>) -> Self {
        UidSetMember::UidRange(x)
    }
}

impl From<u32> for UidSetMember {
    fn from(x: u32) -> Self {
        UidSetMember::Uid(x)
    }
}

impl<'a> ResponseCode<'a> {
    pub fn into_owned(self) -> ResponseCode<'static> {
        match self {
            ResponseCode::Alert => ResponseCode::Alert,
            ResponseCode::BadCharset(v) => {
                ResponseCode::BadCharset(v.map(|vs| vs.into_iter().map(to_owned_cow).collect()))
            }
            ResponseCode::Capabilities(v) => {
                ResponseCode::Capabilities(v.into_iter().map(Capability::into_owned).collect())
            }
            ResponseCode::HighestModSeq(v) => ResponseCode::HighestModSeq(v),
            ResponseCode::Parse => ResponseCode::Parse,
            ResponseCode::PermanentFlags(v) => {
                ResponseCode::PermanentFlags(v.into_iter().map(to_owned_cow).collect())
            }
            ResponseCode::ReadOnly => ResponseCode::ReadOnly,
            ResponseCode::ReadWrite => ResponseCode::ReadWrite,
            ResponseCode::TryCreate => ResponseCode::TryCreate,
            ResponseCode::UidNext(v) => ResponseCode::UidNext(v),
            ResponseCode::UidValidity(v) => ResponseCode::UidValidity(v),
            ResponseCode::Unseen(v) => ResponseCode::Unseen(v),
            ResponseCode::AppendUid(a, b) => ResponseCode::AppendUid(a, b),
            ResponseCode::CopyUid(a, b, c) => ResponseCode::CopyUid(a, b, c),
            ResponseCode::UidNotSticky => ResponseCode::UidNotSticky,
            ResponseCode::UidRequired => ResponseCode::UidRequired,
            ResponseCode::MessageLimit { limit, last_uid } => {
                ResponseCode::MessageLimit { limit, last_uid }
            }
            ResponseCode::MetadataLongEntries(v) => ResponseCode::MetadataLongEntries(v),
            ResponseCode::MetadataMaxSize(v) => ResponseCode::MetadataMaxSize(v),
            ResponseCode::MetadataTooMany => ResponseCode::MetadataTooMany,
            ResponseCode::MetadataNoPrivate => ResponseCode::MetadataNoPrivate,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
#[non_exhaustive]
pub enum StatusAttribute {
    HighestModSeq(u64), // RFC 4551
    Messages(u32),
    Recent(u32),
    UidNext(u32),
    UidValidity(u32),
    Unseen(u32),
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Metadata {
    pub entry: String,
    pub value: Option<String>,
}

#[derive(Debug, Eq, PartialEq, Clone)]
#[non_exhaustive]
pub enum MailboxDatum<'a> {
    Exists(u32),
    Flags(Vec<Cow<'a, str>>),
    List {
        name_attributes: Vec<NameAttribute<'a>>,
        delimiter: Option<Cow<'a, str>>,
        name: Cow<'a, str>,
    },
    Search(Vec<u32>),
    Sort(Vec<u32>),
    Status {
        mailbox: Cow<'a, str>,
        status: Vec<StatusAttribute>,
    },
    Recent(u32),
    MetadataSolicited {
        mailbox: Cow<'a, str>,
        values: Vec<Metadata>,
    },
    MetadataUnsolicited {
        mailbox: Cow<'a, str>,
        values: Vec<Cow<'a, str>>,
    },
    GmailLabels(Vec<Cow<'a, str>>),
    GmailMsgId(u64),
    GmailThrId(u64),
}

impl<'a> MailboxDatum<'a> {
    pub fn into_owned(self) -> MailboxDatum<'static> {
        match self {
            MailboxDatum::Exists(seq) => MailboxDatum::Exists(seq),
            MailboxDatum::Flags(flags) => {
                MailboxDatum::Flags(flags.into_iter().map(to_owned_cow).collect())
            }
            MailboxDatum::List {
                name_attributes,
                delimiter,
                name,
            } => MailboxDatum::List {
                name_attributes: name_attributes
                    .into_iter()
                    .map(|named_attribute| named_attribute.into_owned())
                    .collect(),
                delimiter: delimiter.map(to_owned_cow),
                name: to_owned_cow(name),
            },
            MailboxDatum::Search(seqs) => MailboxDatum::Search(seqs),
            MailboxDatum::Sort(seqs) => MailboxDatum::Sort(seqs),
            MailboxDatum::Status { mailbox, status } => MailboxDatum::Status {
                mailbox: to_owned_cow(mailbox),
                status,
            },
            MailboxDatum::Recent(seq) => MailboxDatum::Recent(seq),
            MailboxDatum::MetadataSolicited { mailbox, values } => {
                MailboxDatum::MetadataSolicited {
                    mailbox: to_owned_cow(mailbox),
                    values,
                }
            }
            MailboxDatum::MetadataUnsolicited { mailbox, values } => {
                MailboxDatum::MetadataUnsolicited {
                    mailbox: to_owned_cow(mailbox),
                    values: values.into_iter().map(to_owned_cow).collect(),
                }
            }
            MailboxDatum::GmailLabels(labels) => {
                MailboxDatum::GmailLabels(labels.into_iter().map(to_owned_cow).collect())
            }
            MailboxDatum::GmailMsgId(msgid) => MailboxDatum::GmailMsgId(msgid),
            MailboxDatum::GmailThrId(thrid) => MailboxDatum::GmailThrId(thrid),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub enum Capability<'a> {
    Imap4rev1,
    Auth(Cow<'a, str>),
    Atom(Cow<'a, str>),
}

impl<'a> Capability<'a> {
    pub fn into_owned(self) -> Capability<'static> {
        match self {
            Capability::Imap4rev1 => Capability::Imap4rev1,
            Capability::Auth(v) => Capability::Auth(to_owned_cow(v)),
            Capability::Atom(v) => Capability::Atom(to_owned_cow(v)),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Attribute {
    Body,
    Envelope,
    Flags,
    InternalDate,
    ModSeq, // RFC 4551, section 3.3.2
    Rfc822,
    Rfc822Size,
    Rfc822Text,
    Uid,
    /// https://developers.google.com/gmail/imap/imap-extensions#access_to_gmail_labels_x-gm-labels
    GmailLabels,
    GmailMsgId,
    GmailThrId,
}

#[derive(Debug, Eq, PartialEq)]
pub enum MessageSection {
    Header,
    Mime,
    Text,
}

#[derive(Debug, Eq, PartialEq)]
pub enum SectionPath {
    Full(MessageSection),
    Part(Vec<u32>, Option<MessageSection>),
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AttributeValue<'a> {
    BodySection {
        section: Option<SectionPath>,
        index: Option<u32>,
        data: Option<Cow<'a, [u8]>>,
    },
    BodyStructure(BodyStructure<'a>),
    Envelope(Box<Envelope<'a>>),
    Flags(Vec<Cow<'a, str>>),
    InternalDate(Cow<'a, str>),
    ModSeq(u64), // RFC 4551, section 3.3.2
    Rfc822(Option<Cow<'a, [u8]>>),
    Rfc822Header(Option<Cow<'a, [u8]>>),
    Rfc822Size(u32),
    Rfc822Text(Option<Cow<'a, [u8]>>),
    Uid(u32),
    /// https://developers.google.com/gmail/imap/imap-extensions#access_to_gmail_labels_x-gm-labels
    GmailLabels(Vec<Cow<'a, str>>),
    GmailMsgId(u64),
    GmailThrId(u64),
    /// RFC 8474 §5.1 — `EMAILID`: a server-assigned unique identifier for
    /// a message. RFC 8474 mandates that the server can always provide an
    /// EMAILID for any stored message, so this variant is non-optional.
    EmailId(Cow<'a, str>),
    /// RFC 8474 §5.2 — `THREADID`: a server-assigned identifier for the
    /// thread a message belongs to.  `None` corresponds to the wire-form
    /// `THREADID NIL`, which RFC 8474 §5.2 mandates for messages that do
    /// not currently have a thread association.
    ThreadId(Option<Cow<'a, str>>),
    /// An unknown or not-yet-supported FETCH attribute.
    ///
    /// Returned for any `msg-att` token that the parser does not explicitly
    /// recognise (e.g. `SAVEDATE` from RFC 8514, or any future extension).
    /// The name and raw value are consumed and discarded so that the rest
    /// of the `FETCH` attribute list can be parsed without error.  Callers
    /// that need the raw value should match on the specific RFC extension
    /// and open a tracking issue or PR.
    Unknown,
}

impl<'a> AttributeValue<'a> {
    pub fn into_owned(self) -> AttributeValue<'static> {
        match self {
            AttributeValue::BodySection {
                section,
                index,
                data,
            } => AttributeValue::BodySection {
                section,
                index,
                data: data.map(to_owned_cow),
            },
            AttributeValue::BodyStructure(body) => AttributeValue::BodyStructure(body.into_owned()),
            AttributeValue::Envelope(e) => AttributeValue::Envelope(Box::new(e.into_owned())),
            AttributeValue::Flags(v) => {
                AttributeValue::Flags(v.into_iter().map(to_owned_cow).collect())
            }
            AttributeValue::InternalDate(v) => AttributeValue::InternalDate(to_owned_cow(v)),
            AttributeValue::ModSeq(v) => AttributeValue::ModSeq(v),
            AttributeValue::Rfc822(v) => AttributeValue::Rfc822(v.map(to_owned_cow)),
            AttributeValue::Rfc822Header(v) => AttributeValue::Rfc822Header(v.map(to_owned_cow)),
            AttributeValue::Rfc822Size(v) => AttributeValue::Rfc822Size(v),
            AttributeValue::Rfc822Text(v) => AttributeValue::Rfc822Text(v.map(to_owned_cow)),
            AttributeValue::Uid(v) => AttributeValue::Uid(v),
            AttributeValue::GmailLabels(v) => {
                AttributeValue::GmailLabels(v.into_iter().map(to_owned_cow).collect())
            }
            AttributeValue::GmailMsgId(v) => AttributeValue::GmailMsgId(v),
            AttributeValue::GmailThrId(v) => AttributeValue::GmailThrId(v),
            AttributeValue::EmailId(v) => AttributeValue::EmailId(to_owned_cow(v)),
            AttributeValue::ThreadId(v) => AttributeValue::ThreadId(v.map(to_owned_cow)),
            AttributeValue::Unknown => AttributeValue::Unknown,
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq)]
pub enum BodyStructure<'a> {
    Basic {
        common: BodyContentCommon<'a>,
        other: BodyContentSinglePart<'a>,
        extension: Option<BodyExtension<'a>>,
    },
    Text {
        common: BodyContentCommon<'a>,
        other: BodyContentSinglePart<'a>,
        lines: u32,
        extension: Option<BodyExtension<'a>>,
    },
    Message {
        common: BodyContentCommon<'a>,
        other: BodyContentSinglePart<'a>,
        envelope: Envelope<'a>,
        body: Box<BodyStructure<'a>>,
        lines: u32,
        extension: Option<BodyExtension<'a>>,
    },
    Multipart {
        common: BodyContentCommon<'a>,
        bodies: Vec<BodyStructure<'a>>,
        extension: Option<BodyExtension<'a>>,
    },
}

impl<'a> BodyStructure<'a> {
    pub fn into_owned(self) -> BodyStructure<'static> {
        match self {
            BodyStructure::Basic {
                common,
                other,
                extension,
            } => BodyStructure::Basic {
                common: common.into_owned(),
                other: other.into_owned(),
                extension: extension.map(|v| v.into_owned()),
            },
            BodyStructure::Text {
                common,
                other,
                lines,
                extension,
            } => BodyStructure::Text {
                common: common.into_owned(),
                other: other.into_owned(),
                lines,
                extension: extension.map(|v| v.into_owned()),
            },
            BodyStructure::Message {
                common,
                other,
                envelope,
                body,
                lines,
                extension,
            } => BodyStructure::Message {
                common: common.into_owned(),
                other: other.into_owned(),
                envelope: envelope.into_owned(),
                body: Box::new(body.into_owned()),
                lines,
                extension: extension.map(|v| v.into_owned()),
            },
            BodyStructure::Multipart {
                common,
                bodies,
                extension,
            } => BodyStructure::Multipart {
                common: common.into_owned(),
                bodies: bodies.into_iter().map(|v| v.into_owned()).collect(),
                extension: extension.map(|v| v.into_owned()),
            },
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct BodyContentCommon<'a> {
    pub ty: ContentType<'a>,
    pub disposition: Option<ContentDisposition<'a>>,
    pub language: Option<Vec<Cow<'a, str>>>,
    pub location: Option<Cow<'a, str>>,
}

impl<'a> BodyContentCommon<'a> {
    pub fn into_owned(self) -> BodyContentCommon<'static> {
        BodyContentCommon {
            ty: self.ty.into_owned(),
            disposition: self.disposition.map(|v| v.into_owned()),
            language: self
                .language
                .map(|v| v.into_iter().map(to_owned_cow).collect()),
            location: self.location.map(to_owned_cow),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct BodyContentSinglePart<'a> {
    pub id: Option<Cow<'a, str>>,
    pub md5: Option<Cow<'a, str>>,
    pub description: Option<Cow<'a, str>>,
    pub transfer_encoding: ContentEncoding<'a>,
    pub octets: u32,
}

impl<'a> BodyContentSinglePart<'a> {
    pub fn into_owned(self) -> BodyContentSinglePart<'static> {
        BodyContentSinglePart {
            id: self.id.map(to_owned_cow),
            md5: self.md5.map(to_owned_cow),
            description: self.description.map(to_owned_cow),
            transfer_encoding: self.transfer_encoding.into_owned(),
            octets: self.octets,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ContentType<'a> {
    pub ty: Cow<'a, str>,
    pub subtype: Cow<'a, str>,
    pub params: BodyParams<'a>,
}

impl<'a> ContentType<'a> {
    pub fn into_owned(self) -> ContentType<'static> {
        ContentType {
            ty: to_owned_cow(self.ty),
            subtype: to_owned_cow(self.subtype),
            params: body_param_owned(self.params),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ContentDisposition<'a> {
    pub ty: Cow<'a, str>,
    pub params: BodyParams<'a>,
}

impl<'a> ContentDisposition<'a> {
    pub fn into_owned(self) -> ContentDisposition<'static> {
        ContentDisposition {
            ty: to_owned_cow(self.ty),
            params: body_param_owned(self.params),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ContentEncoding<'a> {
    SevenBit,
    EightBit,
    Binary,
    Base64,
    QuotedPrintable,
    Other(Cow<'a, str>),
}

impl<'a> ContentEncoding<'a> {
    pub fn into_owned(self) -> ContentEncoding<'static> {
        match self {
            ContentEncoding::SevenBit => ContentEncoding::SevenBit,
            ContentEncoding::EightBit => ContentEncoding::EightBit,
            ContentEncoding::Binary => ContentEncoding::Binary,
            ContentEncoding::Base64 => ContentEncoding::Base64,
            ContentEncoding::QuotedPrintable => ContentEncoding::QuotedPrintable,
            ContentEncoding::Other(v) => ContentEncoding::Other(to_owned_cow(v)),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum BodyExtension<'a> {
    Num(u32),
    Str(Option<Cow<'a, str>>),
    List(Vec<BodyExtension<'a>>),
}

impl<'a> BodyExtension<'a> {
    pub fn into_owned(self) -> BodyExtension<'static> {
        match self {
            BodyExtension::Num(v) => BodyExtension::Num(v),
            BodyExtension::Str(v) => BodyExtension::Str(v.map(to_owned_cow)),
            BodyExtension::List(v) => {
                BodyExtension::List(v.into_iter().map(|v| v.into_owned()).collect())
            }
        }
    }
}

pub type BodyParams<'a> = Option<Vec<(Cow<'a, str>, Cow<'a, str>)>>;

fn body_param_owned(v: BodyParams<'_>) -> BodyParams<'static> {
    v.map(|v| {
        v.into_iter()
            .map(|(k, v)| (to_owned_cow(k), to_owned_cow(v)))
            .collect()
    })
}

/// An RFC 2822 envelope
///
/// See https://datatracker.ietf.org/doc/html/rfc2822#section-3.6 for more details.
#[derive(Debug, Eq, PartialEq)]
pub struct Envelope<'a> {
    pub date: Option<Cow<'a, [u8]>>,
    pub subject: Option<Cow<'a, [u8]>>,
    /// Author of the message; mailbox responsible for writing the message
    pub from: Option<Vec<Address<'a>>>,
    /// Mailbox of the agent responsible for the message's transmission
    pub sender: Option<Vec<Address<'a>>>,
    /// Mailbox that the author of the message suggests replies be sent to
    pub reply_to: Option<Vec<Address<'a>>>,
    pub to: Option<Vec<Address<'a>>>,
    pub cc: Option<Vec<Address<'a>>>,
    pub bcc: Option<Vec<Address<'a>>>,
    pub in_reply_to: Option<Cow<'a, [u8]>>,
    pub message_id: Option<Cow<'a, [u8]>>,
}

impl<'a> Envelope<'a> {
    pub fn into_owned(self) -> Envelope<'static> {
        Envelope {
            date: self.date.map(to_owned_cow),
            subject: self.subject.map(to_owned_cow),
            from: self
                .from
                .map(|v| v.into_iter().map(|v| v.into_owned()).collect()),
            sender: self
                .sender
                .map(|v| v.into_iter().map(|v| v.into_owned()).collect()),
            reply_to: self
                .reply_to
                .map(|v| v.into_iter().map(|v| v.into_owned()).collect()),
            to: self
                .to
                .map(|v| v.into_iter().map(|v| v.into_owned()).collect()),
            cc: self
                .cc
                .map(|v| v.into_iter().map(|v| v.into_owned()).collect()),
            bcc: self
                .bcc
                .map(|v| v.into_iter().map(|v| v.into_owned()).collect()),
            in_reply_to: self.in_reply_to.map(to_owned_cow),
            message_id: self.message_id.map(to_owned_cow),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Address<'a> {
    pub name: Option<Cow<'a, [u8]>>,
    pub adl: Option<Cow<'a, [u8]>>,
    pub mailbox: Option<Cow<'a, [u8]>>,
    pub host: Option<Cow<'a, [u8]>>,
}

impl<'a> Address<'a> {
    pub fn into_owned(self) -> Address<'static> {
        Address {
            name: self.name.map(to_owned_cow),
            adl: self.adl.map(to_owned_cow),
            mailbox: self.mailbox.map(to_owned_cow),
            host: self.host.map(to_owned_cow),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestId(pub String);

impl RequestId {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    NotAuthenticated,
    Authenticated,
    Selected,
    Logout,
}

// Body Structure

pub struct BodyFields<'a> {
    pub param: BodyParams<'a>,
    pub id: Option<Cow<'a, str>>,
    pub description: Option<Cow<'a, str>>,
    pub transfer_encoding: ContentEncoding<'a>,
    pub octets: u32,
}

impl<'a> BodyFields<'a> {
    pub fn into_owned(self) -> BodyFields<'static> {
        BodyFields {
            param: body_param_owned(self.param),
            id: self.id.map(to_owned_cow),
            description: self.description.map(to_owned_cow),
            transfer_encoding: self.transfer_encoding.into_owned(),
            octets: self.octets,
        }
    }
}

pub struct BodyExt1Part<'a> {
    pub md5: Option<Cow<'a, str>>,
    pub disposition: Option<ContentDisposition<'a>>,
    pub language: Option<Vec<Cow<'a, str>>>,
    pub location: Option<Cow<'a, str>>,
    pub extension: Option<BodyExtension<'a>>,
}

impl<'a> BodyExt1Part<'a> {
    pub fn into_owned(self) -> BodyExt1Part<'static> {
        BodyExt1Part {
            md5: self.md5.map(to_owned_cow),
            disposition: self.disposition.map(|v| v.into_owned()),
            language: self
                .language
                .map(|v| v.into_iter().map(to_owned_cow).collect()),
            location: self.location.map(to_owned_cow),
            extension: self.extension.map(|v| v.into_owned()),
        }
    }
}

pub struct BodyExtMPart<'a> {
    pub param: BodyParams<'a>,
    pub disposition: Option<ContentDisposition<'a>>,
    pub language: Option<Vec<Cow<'a, str>>>,
    pub location: Option<Cow<'a, str>>,
    pub extension: Option<BodyExtension<'a>>,
}

impl<'a> BodyExtMPart<'a> {
    pub fn into_owned(self) -> BodyExtMPart<'static> {
        BodyExtMPart {
            param: body_param_owned(self.param),
            disposition: self.disposition.map(|v| v.into_owned()),
            language: self
                .language
                .map(|v| v.into_iter().map(to_owned_cow).collect()),
            location: self.location.map(to_owned_cow),
            extension: self.extension.map(|v| v.into_owned()),
        }
    }
}

/// The name attributes are returned as part of a LIST response described in
/// [RFC 3501 section 7.2.2](https://tools.ietf.org/html/rfc3501#section-7.2.2).
///
/// This enumeration additional includes values from the extension Special-Use
/// Mailboxes [RFC 6154 section 2](https://tools.ietf.org/html/rfc6154#section-2).
#[derive(Debug, Eq, PartialEq, Clone)]
#[non_exhaustive]
pub enum NameAttribute<'a> {
    /// From [RFC 3501 section 7.2.2](https://tools.ietf.org/html/rfc3501#section-7.2.2):
    ///
    /// > It is not possible for any child levels of hierarchy to exist
    /// > under this name; no child levels exist now and none can be
    /// > created in the future.
    NoInferiors,
    /// From [RFC 3501 section 7.2.2](https://tools.ietf.org/html/rfc3501#section-7.2.2):
    ///
    /// > It is not possible to use this name as a selectable mailbox.
    NoSelect,
    /// From [RFC 3501 section 7.2.2](https://tools.ietf.org/html/rfc3501#section-7.2.2):
    ///
    /// > The mailbox has been marked "interesting" by the server; the
    /// > mailbox probably contains messages that have been added since
    /// > the last time the mailbox was selected.
    Marked,
    /// From [RFC 3501 section 7.2.2](https://tools.ietf.org/html/rfc3501#section-7.2.2):
    ///
    /// > The mailbox does not contain any additional messages since the
    /// > last time the mailbox was selected.
    Unmarked,
    /// From [RFC 6154 section 2](https://tools.ietf.org/html/rfc6154#section-2):
    ///
    /// > This mailbox presents all messages in the user's message store.
    /// > Implementations MAY omit some messages, such as, perhaps, those
    /// > in \Trash and \Junk.  When this special use is supported, it is
    /// > almost certain to represent a virtual mailbox.
    All,
    /// From [RFC 6154 section 2](https://tools.ietf.org/html/rfc6154#section-2):
    ///
    /// > This mailbox is used to archive messages.  The meaning of an
    /// > "archival" mailbox is server-dependent; typically, it will be
    /// > used to get messages out of the inbox, or otherwise keep them
    /// > out of the user's way, while still making them accessible.
    Archive,
    /// From [RFC 6154 section 2](https://tools.ietf.org/html/rfc6154#section-2):
    ///
    /// > This mailbox is used to hold draft messages -- typically,
    /// > messages that are being composed but have not yet been sent.  In
    /// > some server implementations, this might be a virtual mailbox,
    /// > containing messages from other mailboxes that are marked with
    /// > the "\Draft" message flag.  Alternatively, this might just be
    /// > advice that a client put drafts here.
    Drafts,
    /// From [RFC 6154 section 2](https://tools.ietf.org/html/rfc6154#section-2):
    ///
    /// > This mailbox presents all messages marked in some way as
    /// > "important".  When this special use is supported, it is likely
    /// > to represent a virtual mailbox collecting messages (from other
    /// > mailboxes) that are marked with the "\Flagged" message flag.
    Flagged,
    /// From [RFC 6154 section 2](https://tools.ietf.org/html/rfc6154#section-2):
    ///
    /// > This mailbox is where messages deemed to be junk mail are held.
    /// > Some server implementations might put messages here
    /// > automatically.  Alternatively, this might just be advice to a
    /// > client-side spam filter.
    Junk,
    /// From [RFC 6154 section 2](https://tools.ietf.org/html/rfc6154#section-2):
    ///
    /// > This mailbox is used to hold copies of messages that have been
    /// > sent.  Some server implementations might put messages here
    /// > automatically.  Alternatively, this might just be advice that a
    /// > client save sent messages here.
    Sent,
    /// From [RFC 6154 section 2](https://tools.ietf.org/html/rfc6154#section-2)
    ///
    /// > This mailbox is used to hold messages that have been deleted or
    /// > marked for deletion.  In some server implementations, this might
    /// > be a virtual mailbox, containing messages from other mailboxes
    /// > that are marked with the "\Deleted" message flag.
    /// > Alternatively, this might just be advice that a client that
    /// > chooses not to use the IMAP "\Deleted" model should use this as
    /// > its trash location.  In server implementations that strictly
    /// > expect the IMAP "\Deleted" model, this special use is likely not
    /// > to be supported.
    Trash,
    /// A name attribute not defined in [RFC 3501 section 7.2.2](https://tools.ietf.org/html/rfc3501#section-7.2.2)
    /// or any supported extension.
    Extension(Cow<'a, str>),
}

impl<'a> NameAttribute<'a> {
    pub fn into_owned(self) -> NameAttribute<'static> {
        match self {
            // RFC 3501
            NameAttribute::NoInferiors => NameAttribute::NoInferiors,
            NameAttribute::NoSelect => NameAttribute::NoSelect,
            NameAttribute::Marked => NameAttribute::Marked,
            NameAttribute::Unmarked => NameAttribute::Unmarked,
            // RFC 6154
            NameAttribute::All => NameAttribute::All,
            NameAttribute::Archive => NameAttribute::Archive,
            NameAttribute::Drafts => NameAttribute::Drafts,
            NameAttribute::Flagged => NameAttribute::Flagged,
            NameAttribute::Junk => NameAttribute::Junk,
            NameAttribute::Sent => NameAttribute::Sent,
            NameAttribute::Trash => NameAttribute::Trash,
            // Extensions not supported by this crate
            NameAttribute::Extension(s) => NameAttribute::Extension(to_owned_cow(s)),
        }
    }
}

// IMAP4 QUOTA extension (rfc2087)

/// https://tools.ietf.org/html/rfc2087#section-3
#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub enum QuotaResourceName<'a> {
    /// Sum of messages' RFC822.SIZE, in units of 1024 octets
    Storage,
    /// Number of messages
    Message,
    Atom(Cow<'a, str>),
}

impl<'a> QuotaResourceName<'a> {
    pub fn into_owned(self) -> QuotaResourceName<'static> {
        match self {
            QuotaResourceName::Message => QuotaResourceName::Message,
            QuotaResourceName::Storage => QuotaResourceName::Storage,
            QuotaResourceName::Atom(v) => QuotaResourceName::Atom(to_owned_cow(v)),
        }
    }
}

/// 5.1. QUOTA Response (https://tools.ietf.org/html/rfc2087#section-5.1)
#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct QuotaResource<'a> {
    pub name: QuotaResourceName<'a>,
    /// current usage of the resource
    pub usage: u64,
    /// resource limit
    pub limit: u64,
}

impl<'a> QuotaResource<'a> {
    pub fn into_owned(self) -> QuotaResource<'static> {
        QuotaResource {
            name: self.name.into_owned(),
            usage: self.usage,
            limit: self.limit,
        }
    }
}

/// 5.1. QUOTA Response (https://tools.ietf.org/html/rfc2087#section-5.1)
#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct Quota<'a> {
    /// quota root name
    pub root_name: Cow<'a, str>,
    pub resources: Vec<QuotaResource<'a>>,
}

impl<'a> Quota<'a> {
    pub fn into_owned(self) -> Quota<'static> {
        Quota {
            root_name: to_owned_cow(self.root_name),
            resources: self.resources.into_iter().map(|r| r.into_owned()).collect(),
        }
    }
}

/// 5.2. QUOTAROOT Response (https://tools.ietf.org/html/rfc2087#section-5.2)
#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct QuotaRoot<'a> {
    /// mailbox name
    pub mailbox_name: Cow<'a, str>,
    /// zero or more quota root names
    pub quota_root_names: Vec<Cow<'a, str>>,
}

impl<'a> QuotaRoot<'a> {
    pub fn into_owned(self) -> QuotaRoot<'static> {
        QuotaRoot {
            mailbox_name: to_owned_cow(self.mailbox_name),
            quota_root_names: self
                .quota_root_names
                .into_iter()
                .map(to_owned_cow)
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attribute_value_unknown_into_owned() {
        assert_eq!(
            AttributeValue::Unknown.into_owned(),
            AttributeValue::Unknown
        );
    }

    /// Tests that the [`NameAttribute::into_owned`] method returns the
    /// same value (the ownership should only change).
    #[test]
    fn test_name_attribute_into_owned() {
        let name_attributes = [
            // RFC 3501
            NameAttribute::NoInferiors,
            NameAttribute::NoSelect,
            NameAttribute::Marked,
            NameAttribute::Unmarked,
            // RFC 6154
            NameAttribute::All,
            NameAttribute::Archive,
            NameAttribute::Drafts,
            NameAttribute::Flagged,
            NameAttribute::Junk,
            NameAttribute::Sent,
            NameAttribute::Trash,
            // Extensions not supported by this crate
            NameAttribute::Extension(Cow::Borrowed("Foobar")),
        ];

        for name_attribute in name_attributes {
            let owned_name_attribute = name_attribute.clone().into_owned();
            assert_eq!(name_attribute, owned_name_attribute);
        }
    }
}
