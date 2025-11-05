use env_logger::Env;
use log::{debug, error, info, warn};
use std::{
    fs::OpenOptions, io::{Read, Write}, net::{TcpListener, TcpStream}, os::linux::raw::stat, thread, time::{Duration, SystemTime, UNIX_EPOCH}
};

/// Protocol control characters.
const SOH: u8 = 0x01;
const STX: u8 = 0x02;
const ETX: u8 = 0x03;

/// Represents a parsed protocol frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolFrame {
    pub soh: u8,          // should be 0x01
    pub address: u8,      // included in LRC calculation
    pub stx: u8,          // should be 0x02
    pub ctrl: u8,         // included in LRC calculation
    pub message: Vec<u8>, // variable-length payload
    pub etx: u8,          // should be 0x03
    pub lrc: u8,          // 1 byte checksum as transmitted
}

impl ProtocolFrame {
    /// Compute LRC for a byte slice using the protocol rule:
    /// XOR all bytes, mask with 0x7F, then if < 32 add 32.
    ///
    /// This function implements the canonical transformation and can be
    /// used for both constructing and validating frames.
    pub fn compute_lrc_bytes(bytes: &[u8]) -> u8 {
        let mut xor: u8 = 0;
        for &b in bytes {
            xor ^= b;
        }
        let mut lrc = xor & 0x7F;
        if lrc < 32 {
            // use wrapping_add to be explicit about u8 arithmetic
            lrc = lrc.wrapping_add(32);
        }
        lrc
    }

    /// Build the slice of bytes that are used for the LRC calculation:
    /// Address, STX, CTRL, Message..., ETX (SOH excluded, ETX included).
    fn lrc_input_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(3 + self.message.len() + 1);
        v.push(self.address);
        v.push(self.stx);
        v.push(self.ctrl);
        v.extend_from_slice(&self.message);
        v.push(self.etx);
        v
    }

    /// Compute the expected LRC for this frame (based on current fields).
    pub fn expected_lrc(&self) -> u8 {
        let bytes = self.lrc_input_bytes();
        Self::compute_lrc_bytes(&bytes)
    }

    /// Validate the stored LRC against the computed value.
    pub fn validate_lrc(&self) -> bool {
        self.expected_lrc() == self.lrc
    }
}

/// Parse raw byte data into a ProtocolFrame.
fn parse_raw_data(data: &[u8]) -> Result<ProtocolFrame, String> {
    if data.len() < 5 {
        return Err("Data too short to be a valid frame".to_string());
    }

    if data[0] != SOH {
        return Err("Invalid SOH".to_string());
    }

    if data[2] != STX {
        return Err("Invalid STX".to_string());
    }

    if data[data.len() - 2] != ETX {
        return Err("Invalid ETX".to_string());
    }

    let soh = data[0];
    let address = data[1];
    let stx = data[2];
    let ctrl = data[3];
    let message = data[4..data.len() - 2].to_vec();
    let etx = data[data.len() - 2];
    let lrc = data[data.len() - 1];

    let frame = ProtocolFrame {
        soh,
        address,
        stx,
        ctrl,
        message,
        etx,
        lrc,
    };

    if !frame.validate_lrc() {
        return Err("LRC validation failed".to_string());
    }

    Ok(frame)
}

#[derive(Debug)]
struct Message18 {
    id_1: u8,            // First byte of message ID
    id_2: u8,            // Second byte of message ID
    status_word: u8,     // Status word byte
    sports_id: u8,       // This needs to be 5 for basketball
    minutes_1: u8,       // Minutes * 10
    minutes_2: u8,       // Minutes * 1
    seconds_1: u8,       // Seconds * 10
    seconds_2: u8,       // Seconds * 1
    home_time_outs: u8,  // Home time-outs
    guest_time_outs: u8, // Guest time-outs
    byte_11: Option<u8>, // Reserved / unused
    byte_12: Option<u8>, // Reserved / unused
    period: u8,          // Current period
    byte_14: Option<u8>, // Reserved / unused
}

#[derive(Debug)]
struct Message30 {
    id_1: u8,               // First byte of message ID
    id_2: u8,               // Second byte of message ID
    sports_id: u8,          // This needs to be 5 for basketball
    home_score_1: u8,       // Home score position 1
    home_score_2: u8,       // Home score position 2
    home_score_3: u8,       // Home score position 3
    guest_score_1: u8,      // Guest score position 1
    guest_score_2: u8,      // Guest score position 2
    guest_score_3: u8,      // Guest score position 3
}

#[derive(Debug)]
struct Message31{
    id_1: u8,               // First byte of message ID
    id_2: u8,               // Second byte of message ID
    sports_id: u8,          // This needs to be 5 for basketball
    byte_4: Option<u8>,     // Reserved / unused
    home_fouls: u8,         // Home fouls
    byte_6: Option<u8>,     // Reserved / unused
    guest_fouls: u8,        // Guest fouls
    number_player_on_line_1: u8, // Number of player on line position 1
    number_player_on_line_2: u8, // Number of player on line position 2
    number_of_faults_of_player: u8, // Number of faults of player 
    team_of_player: u8,    // Team of player
}

#[derive(Debug)]
struct Message50{
    id_1: u8,               // First byte of message ID
    id_2: u8,               // Second byte of message ID
    status_word: u8,        // Status word
    seconds_1: u8,         // Seconds * 10
    seconds_2: u8,         // Seconds * 1
}

struct StatusWord18 {
    clock_type: bool,          // bit 0
    game_clock_off: bool,      // bit 1
    horn_on: bool,             // bit 2
    possession_in_tenth: bool, // bit 4
    new_match: bool,           // bit 6
    b7: bool,                  // bit 7
}

impl StatusWord18 {
    fn from_byte(byte: u8) -> Self {
        Self {
            clock_type: (byte & (1 << 0)) != 0,
            game_clock_off: (byte & (1 << 1)) != 0,
            horn_on: (byte & (1 << 2)) != 0,
            possession_in_tenth: (byte & (1 << 4)) != 0,
            new_match: (byte & (1 << 6)) != 0,
            b7: (byte & (1 << 7)) != 0,
        }
    }
}

struct StatusWord50 {
    b0: Option<bool>, // bit 0
    status_possession_timer: bool,       
    status_possession_horn: bool,              // bit 2
    status_of_shot_clock: bool,                 // bit 2
    possession_timer_in_tenths: bool,        // bit 4
    b5: Option<bool>,                        // bit 6
    b6: Option<bool>,                        // bit 7
    b7: bool,                                // bit 7
}

impl StatusWord50 {
    fn from_byte(byte: u8) -> Self {
        Self {
            b0: None,
            status_possession_timer: (byte & (1 << 1)) != 0,
            status_possession_horn: (byte & (1 << 2)) != 0,
            status_of_shot_clock: (byte & (1 << 3)) != 0,
            possession_timer_in_tenths: (byte & (1 << 4)) != 0,
            b5: None,
            b6: None,
            b7: (byte & (1 << 7)) != 0,
        }
    }
}

fn parse_valid_frame(frame: ProtocolFrame) {
    // Ensure there's enough data to read the message type
    if frame.message.len() < 2 {
        warn!("Message too short to determine type");
        return;
    }

    // First two bytes of the message indicate the message type
    match (frame.message[0], frame.message[1]) {
        // Message Type 18
        (0x31, 0x38) => {
            info!("Received Message Type 18 (Game Time and Time-outs)");

            // Ensure there's enough data for Message Type 18
            if frame.message.len() < 14 {
                warn!("Message Type 18 too short");
                return;
            }

            // Construct the Message 18 struct
            let message = Message18 {
                id_1: frame.message[0],
                id_2: frame.message[1],
                status_word: frame.message[2],
                sports_id: frame.message[3],
                minutes_1: frame.message[4],
                minutes_2: frame.message[5],
                seconds_1: frame.message[6],
                seconds_2: frame.message[7],
                home_time_outs: frame.message[8],
                guest_time_outs: frame.message[9],
                byte_11: None,
                byte_12: None,
                period: frame.message[12],
                byte_14: None,
            };

            let status_word = StatusWord18::from_byte(message.status_word);

            info!(
                "Status Word - Clock Type: {}, Game Clock Off: {}, Horn On: {}, Possession in Tenth: {}, New Match: {}, B7: {}",
                status_word.clock_type,
                status_word.game_clock_off,
                status_word.horn_on,
                status_word.possession_in_tenth,
                status_word.new_match,
                status_word.b7
            );

            if status_word.game_clock_off {
                info!("Game Clock is OFF");
            } else {
                info!("Game Clock is ON");
            }

            if status_word.possession_in_tenth {
                info!(
                    "{}{}.{}",
                    message.minutes_1 as char, message.minutes_2 as char, message.seconds_2 as char
                );
            } else {
                info!(
                    "{}{}:{}{}",
                    message.minutes_1 as char,
                    message.minutes_2 as char,
                    message.seconds_1 as char,
                    message.seconds_2 as char
                );
            }

            info!(
                "Home Time-outs: {}, Guest Time-outs: {}, Period: {}",
                message.home_time_outs as char,
                message.guest_time_outs as char,
                message.period as char
            );
        }
        // Message Type 30
        (0x33, 0x30) => {
            info!("Received Message Type 30 (Scores)");

            // Ensure there's enough data for Message Type 30
            if frame.message.len() < 9 {
                warn!("Message Type 30 too short");
                return;
            }

            let message = Message30 {
                id_1: frame.message[0],
                id_2: frame.message[1],
                sports_id: frame.message[2],
                home_score_1: frame.message[3],
                home_score_2: frame.message[4],
                home_score_3: frame.message[5],
                guest_score_1: frame.message[6],
                guest_score_2: frame.message[7],
                guest_score_3: frame.message[8],
            };

            info!(
                "Home Score: {}{}{}, Guest Score: {}{}{}",
                message.home_score_1 as char,
                message.home_score_2 as char,
                message.home_score_3 as char,
                message.guest_score_1 as char,
                message.guest_score_2 as char,
                message.guest_score_3 as char
            );
            
        }

        // Message Type 31
        (0x33, 0x31) => {
            info!("Received Message Type 31 (Fouls and Player Info)");

            // Ensure there's enough data for Message Type 31
            if frame.message.len() < 11 {
                warn!("Message Type 31 too short");
                return;
            }

            let message = Message31 {
                id_1: frame.message[0],
                id_2: frame.message[1],
                sports_id: frame.message[2],
                byte_4: None,
                home_fouls: frame.message[4],
                byte_6: None,
                guest_fouls: frame.message[6],
                number_player_on_line_1: frame.message[7],
                number_player_on_line_2: frame.message[8],
                number_of_faults_of_player: frame.message[9],
                team_of_player: frame.message[10],
            };

            info!(
                "Home Fouls: {}, Guest Fouls: {}, Player on Line 1: {}, Player on Line 2: {}, Faults of Player: {}, Team of Player: {}",
                message.home_fouls as char,
                message.guest_fouls as char,
                message.number_player_on_line_1 as char,
                message.number_player_on_line_2 as char,
                message.number_of_faults_of_player as char,
                message.team_of_player as char
            );
        }

        // Message Type 50
        (0x35, 0x30) => {
            info!("Received Message Type 50 (Shot Clock)");

            // Ensure there's enough data for Message Type 50
            if frame.message.len() < 5 {
                warn!("Message Type 50 too short");
                return;
            }

            let message = Message50 {
                id_1: frame.message[0],
                id_2: frame.message[1],
                status_word: frame.message[2],
                seconds_1: frame.message[3],
                seconds_2: frame.message[4],
            };

            let status_word = StatusWord50::from_byte(message.status_word);
            
            // info!(
            //     "Status Word - Clock Type: {}, Game Clock Off: {}, Horn On: {}, Possession in Tenth: {}, New Match: {}, B7: {}",
            //     status_word.clock_type,
            //     status_word.game_clock_off,
            //     status_word.horn_on,
            //     status_word.possession_in_tenth,
            //     status_word.new_match,
            //     status_word.b7
            // );

            if status_word.possession_timer_in_tenths {
                info!(
                    "Shot Clock Time: {}.{}",
                    message.seconds_1 as char, message.seconds_2 as char
                );
            } else {
                info!(
                    "Shot Clock Time: {}{}",
                    message.seconds_1 as char, message.seconds_2 as char
                );
            }
        }



        _ => {
            warn!(
                "Unknown message type: 0x{:02X} 0x{:02X}",
                frame.message[0], frame.message[1]
            );
        }
    }
}

fn main() {
    // Parse command-line args and determine if we're in dev mode.
    // When started with an argument equal to "dev", do NOT log TCP session bytes to files.
    let args: Vec<String> = std::env::args().collect();
    let dev_mode = args.iter().any(|a| a == "dev");

    // Initialize logger (reads RUST_LOG if set, defaults to `debug` level)
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();

    if dev_mode {
        info!("Starting in dev mode: TCP session bytes will NOT be logged to files");
    }

    let tcp_address = "0.0.0.0:4001";

    let listener = TcpListener::bind(&tcp_address).unwrap();
    info!("Basketball Protocol Server listening on {}", tcp_address);
    info!("Waiting for connections...");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                // capture dev_mode (bool is Copy so this is fine)
                thread::spawn(move || {
                    if let Err(e) = handle_client(stream, !dev_mode) {
                        error!("Error handling client: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Error accepting connection: {}", e);
            }
        }
    }
}

// Handle a single client connection
fn handle_client(mut stream: TcpStream, log_to_file: bool) -> std::io::Result<()> {
    let peer_addr = stream.peer_addr()?;
    info!("New connection from: {}", peer_addr);

    // Set read timeout to prevent hanging
    stream.set_read_timeout(Some(Duration::from_secs(300)))?;

    // Create `data_log/` directory and open a new per-session file named with a timestamp
    // only if file logging is enabled. Do not write a header — raw bytes only.
    // Failures to create/open the file are logged and do not terminate the client connection.
    let mut log_file: Option<std::fs::File> = if log_to_file {
        // ensure directory exists
        if let Err(e) = std::fs::create_dir_all("data_log") {
            error!("Failed to create data_log directory: {}", e);
        }

        // timestamp-based filename (seconds + millis to reduce collisions)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let file_name = format!(
            "data_log/session-{}.{}.log",
            now.as_secs(),
            now.subsec_millis()
        );

        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_name)
        {
            Ok(f) => {
                info!("Logging TCP session to {}", file_name);
                Some(f)
            }
            Err(e) => {
                error!("Failed to open session log file {}: {}", file_name, e);
                None
            }
        }
    } else {
        info!("Session file logging is disabled for this run");
        None
    };

    let mut buffer = [0u8; 1024];

    loop {
        match stream.read(&mut buffer) {
            Ok(0) => {
                // Connection closed
                info!("Connection closed by: {}", peer_addr);
                break;
            }
            Ok(n) => {
                // Write each TCP read as a single newline-delimited line containing
                // a hex-style byte array (matching the debug output), e.g.:
                // [01, 7F, 02, ...]
                if let Some(ref mut f) = log_file {
                    let line = format!("{:02X?}\n", &buffer[..n]);
                    if let Err(e) = f.write_all(line.as_bytes()) {
                        warn!("Failed to write raw bytes to log file: {}", e);
                    }
                    // best-effort flush to ensure data is on-disk quickly
                    if let Err(e) = f.flush() {
                        warn!("Failed to flush log file: {}", e);
                    }
                }

                // Attempt to parse the received bytes as a ProtocolFrame
                match parse_raw_data(&buffer[..n]) {
                    Ok(frame) => {
                        // info!(
                        //     "Parsed ProtocolFrame: SOH={:02X}, ADDR={:02X}, STX={:02X}, CTRL={:02X}, MESSAGE={:02X?}, ETX={:02X}, LRC={:02X}",
                        //     frame.soh,
                        //     frame.address,
                        //     frame.stx,
                        //     frame.ctrl,
                        //     frame.message,
                        //     frame.etx,
                        //     frame.lrc
                        // );

                        parse_valid_frame(frame);
                    }
                    Err(e) => {
                        warn!("Failed to parse ProtocolFrame from {}: {}", peer_addr, e);
                    }
                }
            }
            Err(e) => {
                error!("Error reading from {}: {}", peer_addr, e);
                break;
            }
        }
    }

    Ok(())
}
