#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate imap_proto;

// UTF-8
fuzz_target!(|data: &[u8]| {
    use imap_proto::parse_response;
    if let Ok(string_data) = std::str::from_utf8(data) {
        let _ = parse_response(string_data.as_bytes());
    }
});
