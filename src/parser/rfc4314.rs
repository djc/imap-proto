//!
//! Current
//! https://tools.ietf.org/html/rfc4314
//!
//! Original
//! https://tools.ietf.org/html/rfc2086
//!
//! The IMAP ACL Extension
//!

use std::borrow::Cow;

use nom::{
    bytes::streaming::tag_no_case,
    character::complete::{space0, space1},
    combinator::map,
    multi::separated_list0,
    sequence::{preceded, separated_pair},
    IResult, Parser,
};

use crate::parser::core::{astring_utf8, to_owned_cow};
use crate::parser::rfc3501::mailbox;
use crate::parser::Response;

#[derive(Debug, Eq, PartialEq)]
pub struct Acl<'a> {
    pub mailbox: Cow<'a, str>,
    pub acls: Vec<AclEntry<'a>>,
}

impl<'a> Acl<'a> {
    pub fn into_owned(self) -> Acl<'static> {
        Acl {
            mailbox: to_owned_cow(self.mailbox),
            acls: self.acls.into_iter().map(AclEntry::into_owned).collect(),
        }
    }
}

/// 3.6. ACL Response
/// ```ignore
/// acl_response  ::= "ACL" SP mailbox SP acl_list
/// ```
pub(crate) fn acl(i: &[u8]) -> IResult<&[u8], Response<'_>> {
    let (rest, (_, _, mailbox, acls)) = (tag_no_case("ACL"), space1, mailbox, acl_list).parse(i)?;

    Ok((rest, Response::Acl(Acl { mailbox, acls })))
}

/// ```ignore
/// acl_list  ::= *(SP acl_entry)
/// ```
fn acl_list(i: &[u8]) -> IResult<&[u8], Vec<AclEntry<'_>>> {
    preceded(space0, separated_list0(space1, acl_entry)).parse(i)
}

#[derive(Debug, Eq, PartialEq)]
pub struct AclEntry<'a> {
    pub identifier: Cow<'a, str>,
    pub rights: Vec<AclRight>,
}

impl<'a> AclEntry<'a> {
    pub fn into_owned(self) -> AclEntry<'static> {
        AclEntry {
            identifier: to_owned_cow(self.identifier),
            rights: self.rights,
        }
    }
}

/// ```ignore
/// acl_entry ::= SP identifier SP rights
/// ```
fn acl_entry(i: &[u8]) -> IResult<&[u8], AclEntry<'_>> {
    let (rest, (identifier, rights)) = separated_pair(
        astring_utf8,
        space1,
        map(astring_utf8, |s| map_text_to_rights(&s)),
    )
    .parse(i)?;

    Ok((rest, AclEntry { identifier, rights }))
}

#[derive(Debug, Eq, PartialEq)]
pub struct ListRights<'a> {
    pub mailbox: Cow<'a, str>,
    pub identifier: Cow<'a, str>,
    pub required: Vec<AclRight>,
    pub optional: Vec<AclRight>,
}

impl<'a> ListRights<'a> {
    pub fn into_owned(self) -> ListRights<'static> {
        ListRights {
            mailbox: to_owned_cow(self.mailbox),
            identifier: to_owned_cow(self.identifier),
            required: self.required,
            optional: self.optional,
        }
    }
}

/// 3.7. LISTRIGHTS Response
/// ```ignore
/// list_rights_response  ::= "LISTRIGHTS" SP mailbox SP identifier SP required_rights *(SP optional_rights)
/// ```
pub(crate) fn list_rights(i: &[u8]) -> IResult<&[u8], Response<'_>> {
    let (rest, (_, _, mailbox, _, identifier, _, required, optional)) = (
        tag_no_case("LISTRIGHTS"),
        space1,
        mailbox,
        space1,
        astring_utf8,
        space1,
        map(astring_utf8, |s| map_text_to_rights(&s)),
        list_rights_optional,
    )
        .parse(i)?;

    Ok((
        rest,
        Response::ListRights(ListRights {
            mailbox,
            identifier,
            required,
            optional,
        }),
    ))
}

fn list_rights_optional(i: &[u8]) -> IResult<&[u8], Vec<AclRight>> {
    let (rest, items) = preceded(space0, separated_list0(space1, astring_utf8)).parse(i)?;

    Ok((
        rest,
        items
            .into_iter()
            .flat_map(|s| s.chars().map(AclRight::from).collect::<Vec<_>>())
            .collect(),
    ))
}

#[derive(Debug, Eq, PartialEq)]
pub struct MyRights<'a> {
    pub mailbox: Cow<'a, str>,
    pub rights: Vec<AclRight>,
}

impl<'a> MyRights<'a> {
    pub fn into_owned(self) -> MyRights<'static> {
        MyRights {
            mailbox: to_owned_cow(self.mailbox),
            rights: self.rights,
        }
    }
}

/// 3.7. MYRIGHTS Response
/// ```ignore
/// my_rights_response  ::= "MYRIGHTS" SP mailbox SP rights
/// ```
pub(crate) fn my_rights(i: &[u8]) -> IResult<&[u8], Response<'_>> {
    let (rest, (_, _, mailbox, _, rights)) = (
        tag_no_case("MYRIGHTS"),
        space1,
        mailbox,
        space1,
        map(astring_utf8, |s| map_text_to_rights(&s)),
    )
        .parse(i)?;

    Ok((rest, Response::MyRights(MyRights { mailbox, rights })))
}

/// helper routine to map a string to a vec of AclRights
fn map_text_to_rights(i: &str) -> Vec<AclRight> {
    i.chars().map(|c| c.into()).collect()
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum AclRight {
    /// l - lookup (mailbox is visible to LIST/LSUB commands, SUBSCRIBE
    /// mailbox)
    Lookup,
    /// r - read (SELECT the mailbox, perform STATUS)
    Read,
    /// s - keep seen/unseen information across sessions (set or clear
    /// \SEEN flag via STORE, also set \SEEN during APPEND/COPY/
    /// FETCH BODY[...])
    Seen,
    /// w - write (set or clear flags other than \SEEN and \DELETED via
    /// STORE, also set them during APPEND/COPY)
    Write,
    /// i - insert (perform APPEND, COPY into mailbox)
    Insert,
    /// p - post (send mail to submission address for mailbox,
    /// not enforced by IMAP4 itself)
    Post,
    /// k - create mailboxes (CREATE new sub-mailboxes in any
    /// implementation-defined hierarchy, parent mailbox for the new
    /// mailbox name in RENAME)
    CreateMailbox,
    /// x - delete mailbox (DELETE mailbox, old mailbox name in RENAME)
    DeleteMailbox,
    /// t - delete messages (set or clear \DELETED flag via STORE, set
    /// \DELETED flag during APPEND/COPY)
    DeleteMessage,
    /// e - perform EXPUNGE and expunge as a part of CLOSE
    Expunge,
    /// a - administer (perform SETACL/DELETEACL/GETACL/LISTRIGHTS)
    Administer,
    /// n - ability to write .shared annotations values
    /// From RFC 5257
    Annotation,
    /// c - old (deprecated) create. Do not use. Read RFC 4314 for more information.
    OldCreate,
    /// d - old (deprecated) delete. Do not use. Read RFC 4314 for more information.
    OldDelete,
    /// A custom right
    Custom(char),
}

impl From<char> for AclRight {
    fn from(c: char) -> Self {
        match c {
            'l' => AclRight::Lookup,
            'r' => AclRight::Read,
            's' => AclRight::Seen,
            'w' => AclRight::Write,
            'i' => AclRight::Insert,
            'p' => AclRight::Post,
            'k' => AclRight::CreateMailbox,
            'x' => AclRight::DeleteMailbox,
            't' => AclRight::DeleteMessage,
            'e' => AclRight::Expunge,
            'a' => AclRight::Administer,
            'n' => AclRight::Annotation,
            'c' => AclRight::OldCreate,
            'd' => AclRight::OldDelete,
            _ => AclRight::Custom(c),
        }
    }
}

impl From<AclRight> for char {
    fn from(right: AclRight) -> Self {
        match right {
            AclRight::Lookup => 'l',
            AclRight::Read => 'r',
            AclRight::Seen => 's',
            AclRight::Write => 'w',
            AclRight::Insert => 'i',
            AclRight::Post => 'p',
            AclRight::CreateMailbox => 'k',
            AclRight::DeleteMailbox => 'x',
            AclRight::DeleteMessage => 't',
            AclRight::Expunge => 'e',
            AclRight::Administer => 'a',
            AclRight::Annotation => 'n',
            AclRight::OldCreate => 'c',
            AclRight::OldDelete => 'd',
            AclRight::Custom(c) => c,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_char_to_acl_right() {
        assert_eq!(Into::<AclRight>::into('l'), AclRight::Lookup);
        assert_eq!(Into::<AclRight>::into('c'), AclRight::OldCreate);
        assert_eq!(Into::<AclRight>::into('k'), AclRight::CreateMailbox);
        assert_eq!(Into::<AclRight>::into('0'), AclRight::Custom('0'));
    }

    #[test]
    fn test_acl_right_to_char() {
        assert_eq!(Into::<char>::into(AclRight::Lookup), 'l');
        assert_eq!(Into::<char>::into(AclRight::OldCreate), 'c');
        assert_eq!(Into::<char>::into(AclRight::CreateMailbox), 'k');
        assert_eq!(Into::<char>::into(AclRight::Custom('0')), '0');
    }
}
