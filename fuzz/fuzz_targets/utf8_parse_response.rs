#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate imap_proto;

// UTF-8
fuzz_target!(|data: &[u8]| {
    let _ = imap_proto::Response::parse(data);
});
