use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::process;

fn receive(reader: &mut BufReader<TcpStream>) -> String {
    let mut response = String::new();

    match reader.read_line(&mut response) {
        Ok(0) => {
            println!("[FRONTEND] Backend disconnected.");
            process::exit(0);
        }
        Ok(_) => response.trim_end().to_string(),
        Err(error) => {
            eprintln!("[FRONTEND] Failed to receive data: {error}");
            process::exit(1);
        }
    }
}

fn main() {
    println!("========================================");
    println!("       TFHE-RS SECURE COMPUTATION");
    println!("========================================");

    let stream = match TcpStream::connect("127.0.0.1:7878") {
        Ok(stream) => stream,
        Err(error) => {
            eprintln!("[FRONTEND] Could not connect to backend: {error}");
            eprintln!("[FRONTEND] Start the backend terminal first.");
            return;
        }
    };

    let writer_stream = match stream.try_clone() {
        Ok(stream) => stream,
        Err(error) => {
            eprintln!("[FRONTEND] Could not clone connection: {error}");
            return;
        }
    };

    let mut reader = BufReader::new(stream);
    let mut writer = writer_stream;

    println!("[FRONTEND] Connected to backend.");
    println!("\n[FRONTEND] Waiting for backend initialization...");

    // Wait until TFHE key generation is completed.
    loop {
        let response = receive(&mut reader);

        if let Some(message) = response.strip_prefix("STATUS|") {
            println!("[BACKEND STATUS] {message}");
        } else if response == "READY" {
            println!("[BACKEND] Ready for encrypted operations.");
            break;
        } else if let Some(error) = response.strip_prefix("ERROR|") {
            println!("[BACKEND ERROR] {error}");
            return;
        } else {
            println!("[BACKEND] {response}");
        }
    }

    loop {
        println!();
        println!("Choose an operation:");
        println!("1. Addition");
        println!("2. Subtraction");
        println!("3. Multiplication");
        println!("4. Division");
        println!("5. Comparison");
        println!("0. Exit");
        print!("Enter your choice: ");

        if io::stdout().flush().is_err() {
            eprintln!("[FRONTEND] Could not display the prompt.");
            break;
        }

        let mut choice = String::new();

        if io::stdin().read_line(&mut choice).is_err() {
            eprintln!("[FRONTEND] Could not read your choice.");
            break;
        }

        let choice = choice.trim();

        if choice == "0" {
            if let Err(error) = writeln!(writer, "EXIT") {
                eprintln!("[FRONTEND] Could not send exit command: {error}");
                break;
            }

            if let Err(error) = writer.flush() {
                eprintln!("[FRONTEND] Could not flush exit command: {error}");
                break;
            }

            println!("[FRONTEND] Exit command sent to backend.");

            let response = receive(&mut reader);

            if let Some(message) = response.strip_prefix("RESULT|") {
                println!("[FRONTEND] {message}");
            } else {
                println!("[FRONTEND] Backend response: {response}");
            }

            println!("[FRONTEND] Closing frontend.");
            break;
        }

        // Send the numeric operation expected by the backend.
        let operation = match choice {
            "1" => "1",
            "2" => "2",
            "3" => "3",
            "4" => "4",
            "5" => "5",
            _ => {
                println!("[FRONTEND] Invalid choice. Select 0 to 5.");
                continue;
            }
        };

        print!("Enter the first number: ");

        if io::stdout().flush().is_err() {
            break;
        }

        let mut first = String::new();

        if io::stdin().read_line(&mut first).is_err() {
            eprintln!("[FRONTEND] Could not read the first number.");
            continue;
        }

        let first = first.trim();

        print!("Enter the second number: ");

        if io::stdout().flush().is_err() {
            break;
        }

        let mut second = String::new();

        if io::stdin().read_line(&mut second).is_err() {
            eprintln!("[FRONTEND] Could not read the second number.");
            continue;
        }

        let second = second.trim();

        if first.is_empty() || second.is_empty() {
            println!("[FRONTEND] Both numbers are required.");
            continue;
        }

        // The backend handles exact decimal parsing and validation.
        let request = format!("{operation}|{first}|{second}");

        if let Err(error) = writeln!(writer, "{request}") {
            eprintln!("[FRONTEND] Could not send request: {error}");
            break;
        }

        if let Err(error) = writer.flush() {
            eprintln!("[FRONTEND] Could not flush request: {error}");
            break;
        }

        println!();
        println!("[FRONTEND] Request sent to backend.");

        // Receive the backend response.
        loop {
            let response = receive(&mut reader);

            if let Some(message) = response.strip_prefix("STATUS|") {
                println!("[BACKEND STATUS] {message}");
            } else if response == "RESULT|Operation completed" {

                // Read the actual result sent on the next line.
                let value_response = receive(&mut reader);

                if let Some(value) = value_response.strip_prefix("VALUE|") {
                    println!();
                    println!("========== RESULT ==========");
                    println!("{value}");
                    println!("============================");
                } else {
                    println!(
                        "[FRONTEND] Unexpected result: {value_response}"
                    );
                }

                break;
            } else if let Some(error) = response.strip_prefix("ERROR|") {
                println!("[BACKEND ERROR] {error}");
                break;
            } else if response == "READY" {
                println!("[BACKEND] Ready.");
            } else {
                println!("[BACKEND] {response}");
            }
        }
    }

    println!("[FRONTEND] Program ended.");
}