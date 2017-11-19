use FromByteResponse;

#[derive(Debug, Eq, PartialEq)]
pub struct Request(pub RequestId, pub Vec<u8>);

#[derive(Debug, Eq, PartialEq)]
pub enum AttrMacro {
    All,
    Fast,
    Full,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Response<'a, T: FromByteResponse<'a>> {
    Capabilities(Vec<T>),
    Done {
        tag: RequestId,
        status: Status,
        code: Option<ResponseCode<T>>,
        information: Option<T>,
    },
    Data {
        status: Status,
        code: Option<ResponseCode<T>>,
        information: Option<T>,
    },
    Expunge(u32),
    Fetch(u32, Vec<AttributeValue<'a, T>>),
    MailboxData(MailboxDatum<T>),
}

impl<'a> Response<'a, &'a [u8]> {
    pub(crate) fn map_bytes<T: FromByteResponse<'a>>(self) -> Response<'a, T> {
        match self {
            Response::Capabilities(v) => {
                Response::Capabilities(v.into_iter().map(|c| T::from_bytes(c)).collect())
            },
            Response::Done { tag, status, code, information } => Response::Done {
                tag,
                status,
                code: code.map(|rc| rc.map_bytes()),
                information: information.map(|i| T::from_bytes(i)),
            },
            Response::Data { status, code, information } => Response::Data {
                status,
                code: code.map(|rc| rc.map_bytes()),
                information: information.map(|i| T::from_bytes(i)),
            },
            Response::Expunge(e) => Response::Expunge(e),
            Response::Fetch(t, a) => {
                Response::Fetch(t, a.into_iter().map(|av| av.map_bytes()).collect())
            },
            Response::MailboxData(md) => Response::MailboxData(md.map_bytes()),
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
pub enum ResponseCode<T> {
    HighestModSeq(u64), // RFC 4551, section 3.1.1
    PermanentFlags(Vec<T>),
    ReadOnly,
    ReadWrite,
    TryCreate,
    UidNext(u32),
    UidValidity(u32),
    Unseen(u32),
}

impl<'a> ResponseCode<&'a [u8]> {
    pub(crate) fn map_bytes<T: FromByteResponse<'a>>(self) -> ResponseCode<T> {
        match self {
            ResponseCode::HighestModSeq(s) => ResponseCode::HighestModSeq(s),
            ResponseCode::PermanentFlags(f) => {
                ResponseCode::PermanentFlags(f.into_iter().map(|f| T::from_bytes(f)).collect())
            },
            ResponseCode::ReadOnly => ResponseCode::ReadOnly,
            ResponseCode::ReadWrite => ResponseCode::ReadWrite,
            ResponseCode::TryCreate => ResponseCode::TryCreate,
            ResponseCode::UidNext(u) => ResponseCode::UidNext(u),
            ResponseCode::UidValidity(v) => ResponseCode::UidValidity(v),
            ResponseCode::Unseen(n) => ResponseCode::Unseen(n),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum MailboxDatum<T> {
    Exists(u32),
    Flags(Vec<T>),
    List {
        flags: Vec<T>,
        delimiter: T,
        name: T,
    },
    SubList {
        flags: Vec<T>,
        delimiter: T,
        name: T,
    },
    Recent(u32),
}

impl<'a> MailboxDatum<&'a [u8]> {
    pub(crate) fn map_bytes<T: FromByteResponse<'a>>(self) -> MailboxDatum<T> {
        match self {
            MailboxDatum::Exists(e) => MailboxDatum::Exists(e),
            MailboxDatum::Flags(f) => {
                MailboxDatum::Flags(f.into_iter().map(|f| T::from_bytes(f)).collect())
            },
            MailboxDatum::List { flags, delimiter, name } => MailboxDatum::List {
                flags: flags.into_iter().map(|f| T::from_bytes(f)).collect(),
                delimiter: T::from_bytes(delimiter),
                name: T::from_bytes(name),
            },
            MailboxDatum::SubList { flags, delimiter, name } => MailboxDatum::SubList {
                flags: flags.into_iter().map(|f| T::from_bytes(f)).collect(),
                delimiter: T::from_bytes(delimiter),
                name: T::from_bytes(name),
            },
            MailboxDatum::Recent(r) => MailboxDatum::Recent(r),
        }
    }
}


#[derive(Debug, Eq, PartialEq)]
pub enum Attribute {
    Body,
    Envelope,
    Flags,
    InternalDate,
    ModSeq, // RFC 4551, section 3.3.2
    Rfc822,
    Rfc822Size,
    Uid,
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

#[derive(Debug, Eq, PartialEq)]
pub enum AttributeValue<'a, T: FromByteResponse<'a>> {
    BodySection {
        section: Option<SectionPath>,
        index: Option<u32>,
        data: Option<&'a [u8]>,
    },
    Envelope(Envelope<T>),
    Flags(Vec<T>),
    InternalDate(T),
    ModSeq(u64), // RFC 4551, section 3.3.2
    Rfc822(Option<&'a [u8]>),
    Rfc822Size(u32),
    Uid(u32),
}

impl<'a> AttributeValue<'a, &'a [u8]> {
    pub(crate) fn map_bytes<T: FromByteResponse<'a>>(self) -> AttributeValue<'a, T> {
        match self {
            AttributeValue::BodySection { section, index, data } => {
                AttributeValue::BodySection { section, index, data }
            },
            AttributeValue::Envelope(e) => AttributeValue::Envelope(e.map_bytes()),
            AttributeValue::Flags(f) => {
                AttributeValue::Flags(f.into_iter().map(|f| T::from_bytes(f)).collect())
            },
            AttributeValue::InternalDate(d) => AttributeValue::InternalDate(T::from_bytes(d)),
            AttributeValue::ModSeq(ms) => AttributeValue::ModSeq(ms),
            AttributeValue::Rfc822(b) => AttributeValue::Rfc822(b),
            AttributeValue::Rfc822Size(s) => AttributeValue::Rfc822Size(s),
            AttributeValue::Uid(u) => AttributeValue::Uid(u),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Envelope<T> {
    pub date: Option<T>,
    pub subject: Option<T>,
    pub from: Option<Vec<Address<T>>>,
    pub sender: Option<Vec<Address<T>>>,
    pub reply_to: Option<Vec<Address<T>>>,
    pub to: Option<Vec<Address<T>>>,
    pub cc: Option<Vec<Address<T>>>,
    pub bcc: Option<Vec<Address<T>>>,
    pub in_reply_to: Option<T>,
    pub message_id: Option<T>,
}

impl<'a> Envelope<&'a [u8]> {
    pub(crate) fn map_bytes<T: FromByteResponse<'a>>(self) -> Envelope<T> {
        Envelope {
            date: self.date.map(|v| T::from_bytes(v)),
            subject: self.subject.map(|v| T::from_bytes(v)),
            from: self.from
                .map(|addrs| addrs.into_iter().map(|a| a.map_bytes()).collect()),
            sender: self.sender
                .map(|addrs| addrs.into_iter().map(|a| a.map_bytes()).collect()),
            reply_to: self.reply_to
                .map(|addrs| addrs.into_iter().map(|a| a.map_bytes()).collect()),
            to: self.to
                .map(|addrs| addrs.into_iter().map(|a| a.map_bytes()).collect()),
            cc: self.cc
                .map(|addrs| addrs.into_iter().map(|a| a.map_bytes()).collect()),
            bcc: self.bcc
                .map(|addrs| addrs.into_iter().map(|a| a.map_bytes()).collect()),
            in_reply_to: self.in_reply_to.map(|v| T::from_bytes(v)),
            message_id: self.message_id.map(|v| T::from_bytes(v)),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Address<T> {
    pub name: Option<T>,
    pub adl: Option<T>,
    pub mailbox: Option<T>,
    pub host: Option<T>,
}

impl<'a> Address<&'a [u8]> {
    pub(crate) fn map_bytes<T: FromByteResponse<'a>>(self) -> Address<T> {
        Address {
            name: self.name.map(|v| T::from_bytes(v)),
            adl: self.adl.map(|v| T::from_bytes(v)),
            mailbox: self.mailbox.map(|v| T::from_bytes(v)),
            host: self.host.map(|v| T::from_bytes(v)),
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

#[derive(Debug, Eq, PartialEq)]
pub enum State {
    NotAuthenticated,
    Authenticated,
    Selected,
    Logout,
}
