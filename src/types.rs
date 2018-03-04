#[derive(Debug, Eq, PartialEq)]
pub struct Request(pub RequestId, pub Vec<u8>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttrMacro {
    All,
    Fast,
    Full,
}

impl Copy for AttrMacro {}

#[derive(Debug, Eq, PartialEq)]
pub enum Response<'a> {
    Capabilities(Vec<&'a str>),
    Done {
        tag: RequestId,
        status: Status,
        code: Option<ResponseCode<'a>>,
        information: Option<&'a str>,
    },
    Data {
        status: Status,
        code: Option<ResponseCode<'a>>,
        information: Option<&'a str>,
    },
    Expunge(u32),
    Fetch(u32, Vec<AttributeValue<'a>>),
    MailboxData(MailboxDatum<'a>),
    IDs(Vec<u32>),
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
pub enum ResponseCode<'a> {
    HighestModSeq(u64), // RFC 4551, section 3.1.1
    PermanentFlags(Vec<&'a str>),
    ReadOnly,
    ReadWrite,
    TryCreate,
    UidNext(u32),
    UidValidity(u32),
    Unseen(u32),
}

#[derive(Debug, Eq, PartialEq)]
pub enum StatusAttribute {
    Messages(u32),
    Recent(u32),
    UidNext(u32),
    UidValidity(u32),
    Unseen(u32),
}

#[derive(Debug, Eq, PartialEq)]
pub enum MailboxDatum<'a> {
    Exists(u32),
    Flags(Vec<&'a str>),
    List {
        flags: Vec<&'a str>,
        delimiter: &'a str,
        name: &'a str,
    },
    Status {
        mailbox: &'a str,
        status: Vec<StatusAttribute>,
    },
    SubList {
        flags: Vec<&'a str>,
        delimiter: &'a str,
        name: &'a str,
    },
    Recent(u32),
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
pub enum AttributeValue<'a> {
    BodySection {
        section: Option<SectionPath>,
        index: Option<u32>,
        data: Option<&'a [u8]>,
    },
    Envelope(Envelope<'a>),
    Flags(Vec<&'a str>),
    InternalDate(&'a str),
    ModSeq(u64), // RFC 4551, section 3.3.2
    Rfc822(Option<&'a [u8]>),
    Rfc822Size(u32),
    Uid(u32),
}

#[derive(Debug, Eq, PartialEq)]
pub struct Envelope<'a> {
    pub date: Option<&'a str>,
    pub subject: Option<&'a str>,
    pub from: Option<Vec<Address<'a>>>,
    pub sender: Option<Vec<Address<'a>>>,
    pub reply_to: Option<Vec<Address<'a>>>,
    pub to: Option<Vec<Address<'a>>>,
    pub cc: Option<Vec<Address<'a>>>,
    pub bcc: Option<Vec<Address<'a>>>,
    pub in_reply_to: Option<&'a str>,
    pub message_id: Option<&'a str>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Address<'a> {
    pub name: Option<&'a str>,
    pub adl: Option<&'a str>,
    pub mailbox: Option<&'a str>,
    pub host: Option<&'a str>,
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
