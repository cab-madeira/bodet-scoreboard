use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::fs;
use std::sync::{Arc, Mutex};
use std::thread;

use crate::basketball_parser::BasketballProtocol;

/// Web server for basketball overlay
pub struct WebServer {
    address: String,
    state: Arc<Mutex<Option<BasketballProtocol>>>,
}

impl WebServer {
    pub fn new(address: &str, state: Arc<Mutex<Option<BasketballProtocol>>>) -> Self {
        WebServer {
            address: address.to_string(),
            state,
        }
    }

    pub fn start(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(&self.address)?;
        println!("🌐 Web server listening on http://{}", self.address);
        println!("Open this URL in your browser to see the overlay\n");

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let state = Arc::clone(&self.state);
                    thread::spawn(move || {
                        if let Err(e) = handle_http_request(stream, state) {
                            eprintln!("Error handling HTTP request: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Error accepting connection: {}", e);
                }
            }
        }

        Ok(())
    }
}

fn handle_http_request(
    mut stream: TcpStream,
    state: Arc<Mutex<Option<BasketballProtocol>>>,
) -> std::io::Result<()> {
    let mut buffer = [0u8; 1024];
    stream.read(&mut buffer)?;

    let request = String::from_utf8_lossy(&buffer);
    let request_line = request.lines().next().unwrap_or("");

    if request_line.starts_with("GET /api/state") {
        // API endpoint for current game state
        handle_api_request(&mut stream, &state)?;
    } else {
        // Serve the HTML overlay
        handle_overlay_request(&mut stream)?;
    }

    Ok(())
}

fn handle_api_request(
    stream: &mut TcpStream,
    state: &Arc<Mutex<Option<BasketballProtocol>>>,
) -> std::io::Result<()> {
    let current_state = state.lock().unwrap();
    
    let json = if let Some(protocol) = current_state.as_ref() {
        format!(
            r#"{{"home_score":{},"away_score":{},"period":{},"period_name":"{}","time":"{}","home_fouls":{},"away_fouls":{},"home_timeouts":{},"away_timeouts":{},"possession":"{}","game_state":"{}","is_overtime":{},"is_finished":{}}}"#,
            protocol.home_score,
            protocol.away_score,
            protocol.period,
            protocol.period_name(),
            protocol.format_time(),
            protocol.home_fouls,
            protocol.away_fouls,
            protocol.home_timeouts,
            protocol.away_timeouts,
            format!("{:?}", protocol.possession),
            format!("{:?}", protocol.game_state),
            protocol.is_overtime(),
            protocol.is_finished()
        )
    } else {
        r#"{"error":"No game data available"}"#.to_string()
    };

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}",
        json.len(),
        json
    );

    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn handle_overlay_request(stream: &mut TcpStream) -> std::io::Result<()> {
    // Try to read the overlay HTML from disk so updates are served immediately.
    // Check common locations and fall back to the embedded compile-time HTML if necessary.
    let html = match fs::read_to_string("overlay.html") {
        Ok(s) => s,
        Err(_) => match fs::read_to_string("static/overlay.html") {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Warning: could not read overlay.html at runtime: {}\nUsing embedded HTML built into the binary.", e);
                include_str!("../overlay.html").to_string()
            }
        },
    };

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
        html.as_bytes().len(),
        html
    );

    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(())
}
