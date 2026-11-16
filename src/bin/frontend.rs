use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::process;
use tfhe_demo::ADDRESS;

fn receive(reader: &mut BufReader<TcpStream>) -> String {
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) => {
            eprintln!("[FRONTEND] Backend disconnected.");
            process::exit(0);
        }
        Ok(_) => line.trim_end().to_string(),
        Err(e) => {
            eprintln!("[FRONTEND] Receive failed: {e}");
            process::exit(1);
        }
    }
}

fn main() {
    println!("==============================================");
    println!(" TFHE-RS 1.8.1 | ARBITRARY EXPRESSION FRONTEND");
    println!("==============================================");
    let stream = match TcpStream::connect(ADDRESS) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Cannot connect to backend: {e}");
            eprintln!("Start backend first.");
            return;
        }
    };
    let mut reader = BufReader::new(stream.try_clone().expect("clone TCP stream"));
    let mut writer = stream;

    println!("[FRONTEND] Connected. Waiting for backend initialization...");
    loop {
        let line = receive(&mut reader);
        if let Some(s) = line.strip_prefix("STATUS|") {
            println!("[BACKEND STATUS] {s}");
        } else if line == "READY" {
            println!("[BACKEND] Ready.");
            break;
        } else if let Some(e) = line.strip_prefix("ERROR|") {
            eprintln!("[BACKEND ERROR] {e}");
            return;
        } else {
            println!("[BACKEND] {line}");
        }
    }

    loop {
        println!();
        println!("Enter a complete expression (or type exit):");
        println!("Example: 12.50 * 4.25 + 3.10");
        print!("expression> ");
        io::stdout().flush().expect("flush prompt");
        let mut expr = String::new();
        if io::stdin().read_line(&mut expr).unwrap_or(0) == 0 {
            break;
        }
        let expr = expr.trim();
        if expr.eq_ignore_ascii_case("exit") {
            writeln!(writer, "EXIT").ok();
            writer.flush().ok();
            println!("[FRONTEND] Closing.");
            break;
        }
        if expr.is_empty() {
            println!("Enter an expression.");
            continue;
        }
        // Expression is sent as the rest of this line; operators and spaces are preserved.
        if let Err(e) = writeln!(writer, "EXPR|{expr}") {
            eprintln!("Send failed: {e}");
            break;
        }
        if let Err(e) = writer.flush() {
            eprintln!("Flush failed: {e}");
            break;
        }

        loop {
            let line = receive(&mut reader);
            if let Some(s) = line.strip_prefix("STATUS|") {
                println!("[BACKEND STATUS] {s}");
            } else if let Some(v) = line.strip_prefix("VALUE|") {
                println!("\n========== RESULT ==========\n{v}\n============================");
                break;
            } else if let Some(e) = line.strip_prefix("ERROR|") {
                eprintln!("[BACKEND ERROR] {e}");
                break;
            } else if line == "READY" {
                println!("[BACKEND] Ready for next expression.");
                break;
            } else {
                println!("[BACKEND] {line}");
            }
        }
    }
}
