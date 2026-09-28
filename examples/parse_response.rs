use imap_proto::Response;
use std::io::Write;

fn main() -> std::io::Result<()> {
    loop {
        let line = {
            print!("Enter IMAP4REV1 response: ");
            std::io::stdout().flush().unwrap();

            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            line
        };

        match Response::parse(line.replace('\n', "\r\n").as_bytes()) {
            Ok((remaining, command)) => {
                println!("{command:#?}");

                if !remaining.is_empty() {
                    println!("Remaining data in buffer: {remaining:?}");
                }
            }
            Err(_) => {
                println!("Error parsing the response. Is it correct? Exiting.");
                break;
            }
        }
    }

    Ok(())
}
