use std::fs::{File, OpenOptions};
use std::io::{Write, BufWriter};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Result, Context};
use chrono::Local;
use lazy_static::lazy_static;
use regex::Regex;
use structopt::StructOpt;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time;

// ==================== FONCTIONS DE FILTRAGE ====================

/// Filtre pour ne garder que les caractères ASCII imprimables et les espaces blancs
fn filter_printable_chars(input: &str) -> String {
    input.chars()
        .filter(|c| {
            c.is_ascii_graphic() || 
            c.is_ascii_whitespace() || 
            *c == '\n' || 
            *c == '\r' || 
            *c == '\t'
        })
        .collect()
}

/// Remplace les caractères non imprimables par �
fn filter_safe_display(input: &str) -> String {
    input.chars()
        .map(|c| {
            if c.is_ascii_graphic() || c.is_ascii_whitespace() || c == '\n' || c == '\r' {
                c
            } else {
                '�'
            }
        })
        .collect()
}

/// Convertit les caractères non imprimables en séquences d'échappement
fn safe_log_string(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '\0' => result.push_str("\\0"),
            '\x01'..='\x08' | '\x0b' | '\x0c' | '\x0e'..='\x1f' | '\x7f' => {
                result.push_str(&format!("\\x{:02x}", c as u32));
            }
            _ if c.is_ascii_graphic() || c.is_ascii_whitespace() || c == '\n' || c == '\r' => {
                result.push(c);
            }
            _ => {
                result.push_str(&format!("\\u{{{:x}}}", c as u32));
            }
        }
    }
    result
}

// ==================== STRUCTURES PRINCIPALES ====================

#[derive(Debug, StructOpt, Clone)]
#[structopt(
    name = "sip-honeypot",
    about = "A SIP honeypot for detecting and analyzing SIP attacks",
    author = "2026, Philippe TEMESI <https://www.tems.be>",
    version = "0.1.0"
)]
struct Opt {
    /// Run as daemon
    #[structopt(short = "d", long = "daemon")]
    daemon: bool,
    
    /// Listening port (default: 5060)
    #[structopt(short = "p", long = "port", default_value = "5060")]
    port: u16,
    
    /// Log file
    #[structopt(short = "l", long = "log", parse(from_os_str))]
    log_file: Option<PathBuf>,
    
    /// Listening address
    #[structopt(short = "a", long = "address", default_value = "0.0.0.0")]
    address: String,
    
    /// Verbose mode - display SIP details (phone numbers, login, password attempts)
    #[structopt(short = "v", long = "verbose")]
    verbose: bool,
    
    /// Enable raw display (not filtered) - DANGEROUS: can break terminal with control chars
    #[structopt(short = "r", long = "raw")]
    raw_display: bool,
    
    /// Show help
    #[structopt(short = "h", long = "help")]
    help: bool,
    
    /// Show version
    #[structopt(short = "V", long = "version")]
    version: bool,
}

#[derive(Clone)]
struct SipHoneypot {
    socket: Arc<UdpSocket>,
    log_writer: Option<Arc<Mutex<BufWriter<File>>>>,
    verbose: bool,
    raw_display: bool,
}

impl SipHoneypot {
    async fn new(addr: &str, port: u16, log_file: Option<PathBuf>, verbose: bool, raw_display: bool) -> Result<Self> {
        let bind_addr = format!("{}:{}", addr, port);
        let socket = UdpSocket::bind(&bind_addr).await
            .with_context(|| format!("Failed to bind to {}", bind_addr))?;
        
        println!("[INFO] SIP honeypot server started on {}", bind_addr);
        if verbose {
            println!("[INFO] Verbose mode enabled - SIP details will be logged");
        }
        if raw_display {
            println!("[WARNING] Raw display enabled - Terminal may be affected by control characters");
        } else {
            println!("[INFO] Display filtering enabled - Control characters are sanitized");
        }
        
        let log_writer = if let Some(path) = &log_file {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .with_context(|| format!("Failed to open log file: {:?}", path))?;
            println!("[INFO] Logging enabled to: {:?}", path);
            Some(Arc::new(Mutex::new(BufWriter::new(file))))
        } else {
            println!("[INFO] Logging disabled (use -l to enable)");
            None
        };
        
        Ok(Self {
            socket: Arc::new(socket),
            log_writer,
            verbose,
            raw_display,
        })
    }
    
    async fn log(&self, client_addr: &SocketAddr, message: &str) {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        
        // Filtrer le message pour l'affichage
        let display_message = if self.raw_display {
            message.to_string()
        } else {
            filter_printable_chars(message)
        };
        
        let log_line = format!("{} {} {}\n", timestamp, client_addr, display_message);
        
        // Affichage console (filtré ou raw selon option)
        if self.raw_display {
            print!("{}", log_line);
        } else {
            print!("{}", filter_printable_chars(&log_line));
        }
        
        // Écriture fichier (toujours en version originale pour conserver les données)
        if let Some(writer) = &self.log_writer {
            let mut writer = writer.lock().await;
            let file_line = format!("{} {} {}\n", timestamp, client_addr, message);
            if let Err(e) = writer.write_all(file_line.as_bytes()) {
                eprintln!("[ERROR] Log write: {}", e);
            }
            if let Err(e) = writer.flush() {
                eprintln!("[ERROR] Log flush: {}", e);
            }
        }
    }
    
    async fn log_verbose(&self, client_addr: &SocketAddr, title: &str, details: &str) {
        if self.verbose {
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
            let separator = "─".repeat(60);
            
            // Version filtrée pour l'affichage console
            let display_details = if self.raw_display {
                details.to_string()
            } else {
                safe_log_string(details)
            };
            
            let verbose_log = format!(
                "{}\n{} VERBOSE: {} {}\n{}\n{}\n{}\n\n",
                separator,
                timestamp,
                client_addr,
                title,
                separator,
                display_details,
                separator
            );
            
            // Affichage console
            if self.raw_display {
                print!("{}", verbose_log);
            } else {
                print!("{}", filter_printable_chars(&verbose_log));
            }
            
            // Écriture fichier (version safe)
            if let Some(writer) = &self.log_writer {
                let mut writer = writer.lock().await;
                let file_log = format!(
                    "{}\n{} VERBOSE: {} {}\n{}\n{}\n{}\n\n",
                    separator,
                    timestamp,
                    client_addr,
                    title,
                    separator,
                    safe_log_string(details),
                    separator
                );
                if let Err(e) = writer.write_all(file_log.as_bytes()) {
                    eprintln!("[ERROR] Log write: {}", e);
                }
                if let Err(e) = writer.flush() {
                    eprintln!("[ERROR] Log flush: {}", e);
                }
            }
        }
    }
    
    async fn handle_packet(&self, buf: &[u8], client_addr: SocketAddr) {
        let packet_str = String::from_utf8_lossy(buf);
        
        // Log full packet in verbose mode (avec filtrage)
        if self.verbose {
            self.log_verbose(&client_addr, "RAW PACKET", &packet_str).await;
        }
        
        // Version filtrée pour l'analyse SIP
        let check_packet = if self.raw_display {
            packet_str.to_string()
        } else {
            filter_printable_chars(&packet_str)
        };
        
        // Check if it's SIP
        if Self::is_sip_packet(&check_packet) {
            self.log(&client_addr, &format!("SIP packet received ({} bytes)", buf.len())).await;
            
            // Extract and log authentication attempts in verbose mode
            if self.verbose {
                self.extract_and_log_auth_info(&client_addr, &packet_str).await;
            }
            
            // Analyze SIP method
            if let Some(method) = Self::parse_sip_method(&check_packet) {
                self.log(&client_addr, &format!("SIP method detected: {}", method)).await;
                
                // Respond according to method
                let response = match method.as_str() {
                    "REGISTER" => self.handle_register(&packet_str, &client_addr).await,
                    "INVITE" => self.handle_invite(&packet_str, &client_addr).await,
                    "OPTIONS" => self.handle_options(&packet_str, &client_addr).await,
                    "BYE" => self.handle_bye(&packet_str, &client_addr).await,
                    "CANCEL" => self.handle_cancel(&packet_str, &client_addr).await,
                    "ACK" => self.handle_ack(&packet_str, &client_addr).await,
                    "RESPONSE" => self.handle_response(&packet_str, &client_addr).await,
                    _ => self.handle_unknown(&packet_str, &client_addr).await,
                };
                
                if !response.is_empty() {
                    // Log response in verbose mode
                    if self.verbose {
                        self.log_verbose(&client_addr, "RESPONSE", &response).await;
                    }
                    
                    if let Err(e) = self.socket.send_to(response.as_bytes(), client_addr).await {
                        self.log(&client_addr, &format!("Response send error: {}", e)).await;
                    } else {
                        self.log(&client_addr, &format!("Response sent ({} bytes)", response.len())).await;
                    }
                }
            } else {
                self.log(&client_addr, "SIP packet not recognized").await;
            }
        } else {
            self.log(&client_addr, &format!("Non-SIP packet received ({} bytes) - Ignored", buf.len())).await;
        }
    }
    
    async fn extract_and_log_auth_info(&self, client_addr: &SocketAddr, packet: &str) {
        let mut auth_info = Vec::new();
        
        // Extract user/phone number
        if let Some(user) = Self::extract_user_from_packet(packet) {
            auth_info.push(format!("User/Phone: {}", user));
        }
        
        if let Some(to) = Self::extract_to_number(packet) {
            auth_info.push(format!("To number: {}", to));
        }
        
        if let Some(from) = Self::extract_from_user(packet) {
            auth_info.push(format!("From user: {}", from));
        }
        
        // Extract authentication information
        if let Some(auth_header) = Self::extract_authorization_header(packet) {
            auth_info.push(format!("Authorization: {}", auth_header));
            
            if let Some(username) = Self::extract_auth_username(packet) {
                auth_info.push(format!("Auth Username: {}", username));
            }
            
            if let Some(realm) = Self::extract_auth_realm(packet) {
                auth_info.push(format!("Auth Realm: {}", realm));
            }
            
            if let Some(nonce) = Self::extract_auth_nonce(packet) {
                auth_info.push(format!("Auth Nonce: {}", nonce));
            }
            
            if let Some(uri) = Self::extract_auth_uri(packet) {
                auth_info.push(format!("Auth URI: {}", uri));
            }
            
            if let Some(response) = Self::extract_auth_response(packet) {
                auth_info.push(format!("Auth Response (hash): {}", response));
            }
            
            if let Some(algorithm) = Self::extract_auth_algorithm(packet) {
                auth_info.push(format!("Auth Algorithm: {}", algorithm));
            }
        }
        
        // Extract Proxy-Authorization
        if let Some(proxy_auth) = Self::extract_proxy_authorization_header(packet) {
            auth_info.push(format!("Proxy-Authorization: {}", proxy_auth));
        }
        
        // Extract Contact info
        if let Some(contact) = Self::extract_contact_header(packet) {
            auth_info.push(format!("Contact: {}", contact));
        }
        
        // Extract User-Agent
        if let Some(user_agent) = Self::extract_user_agent(packet) {
            auth_info.push(format!("User-Agent: {}", user_agent));
        }
        
        // Extract IP addresses from headers
        if let Some(via) = Self::extract_via_header(packet) {
            auth_info.push(format!("Via: {}", via));
        }
        
        if !auth_info.is_empty() {
            let details = auth_info.join("\n");
            self.log_verbose(client_addr, "SIP DETAILS", &details).await;
        }
    }
    
    // ==================== MÉTHODES D'EXTRACTION SIP ====================
    
    fn extract_authorization_header(packet: &str) -> Option<String> {
        let re = Regex::new(r"(?i)Authorization:\s*(.*?)\r\n").unwrap();
        re.captures(packet)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().trim().to_string())
    }
    
    fn extract_proxy_authorization_header(packet: &str) -> Option<String> {
        let re = Regex::new(r"(?i)Proxy-Authorization:\s*(.*?)\r\n").unwrap();
        re.captures(packet)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().trim().to_string())
    }
    
    fn extract_contact_header(packet: &str) -> Option<String> {
        let re = Regex::new(r"(?i)Contact:\s*(.*?)\r\n").unwrap();
        re.captures(packet)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().trim().to_string())
    }
    
    fn extract_user_agent(packet: &str) -> Option<String> {
        let re = Regex::new(r"(?i)User-Agent:\s*(.*?)\r\n").unwrap();
        re.captures(packet)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().trim().to_string())
    }
    
    fn extract_auth_username(packet: &str) -> Option<String> {
        let re = Regex::new("(?i)username=\"?([^\",]+)\"?").unwrap();
        re.captures(packet)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
    }
    
    fn extract_auth_realm(packet: &str) -> Option<String> {
        let re = Regex::new("(?i)realm=\"?([^\",]+)\"?").unwrap();
        re.captures(packet)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
    }
    
    fn extract_auth_nonce(packet: &str) -> Option<String> {
        let re = Regex::new("(?i)nonce=\"?([^\",]+)\"?").unwrap();
        re.captures(packet)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
    }
    
    fn extract_auth_uri(packet: &str) -> Option<String> {
        let re = Regex::new("(?i)uri=\"?([^\",]+)\"?").unwrap();
        re.captures(packet)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
    }
    
    fn extract_auth_response(packet: &str) -> Option<String> {
        let re = Regex::new("(?i)response=\"?([^\",]+)\"?").unwrap();
        re.captures(packet)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
    }
    
    fn extract_auth_algorithm(packet: &str) -> Option<String> {
        let re = Regex::new("(?i)algorithm=\"?([^\",]+)\"?").unwrap();
        re.captures(packet)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
    }
    
    fn extract_from_user(packet: &str) -> Option<String> {
        let re = Regex::new(r"(?i)From:\s*[^<]*<sip:([^@>]+)").unwrap();
        re.captures(packet)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
    }
    
    // ==================== MÉTHODES D'ANALYSE SIP ====================
    
    fn is_sip_packet(packet: &str) -> bool {
        lazy_static! {
            static ref SIP_REGEX: Regex = Regex::new(r"^(REGISTER|INVITE|ACK|BYE|CANCEL|OPTIONS|SUBSCRIBE|NOTIFY|PUBLISH|MESSAGE|REFER|INFO|PRACK|UPDATE|SIP/2\.0)").unwrap();
        }
        SIP_REGEX.is_match(packet.trim())
    }
    
    fn parse_sip_method(packet: &str) -> Option<String> {
        lazy_static! {
            static ref METHOD_REGEX: Regex = Regex::new(r"^(REGISTER|INVITE|ACK|BYE|CANCEL|OPTIONS|SUBSCRIBE|NOTIFY|PUBLISH|MESSAGE|REFER|INFO|PRACK|UPDATE)").unwrap();
        }
        
        if let Some(caps) = METHOD_REGEX.captures(packet.trim()) {
            caps.get(1).map(|m| m.as_str().to_string())
        } else if packet.contains("SIP/2.0") {
            Some("RESPONSE".to_string())
        } else {
            None
        }
    }
    
    // ==================== GESTIONNAIRES DE MÉTHODES SIP ====================
    
    async fn handle_register(&self, packet: &str, client_addr: &SocketAddr) -> String {
        self.log(client_addr, "Processing REGISTER request").await;
        
        let user = Self::extract_user_from_packet(packet).unwrap_or_else(|| "unknown".to_string());
        
        if self.verbose {
            self.log_verbose(client_addr, "REGISTER ATTEMPT", 
                &format!("User attempting to register: {}", user)).await;
        }
        
        format!("SIP/2.0 200 OK\r\n\
                Via: {}\r\n\
                From: <sip:{}@pbx>\r\n\
                To: <sip:{}@pbx>\r\n\
                Call-ID: {}\r\n\
                CSeq: 1 REGISTER\r\n\
                Contact: <sip:{}@{}:5060>\r\n\
                Expires: 3600\r\n\
                Content-Length: 0\r\n\r\n",
                Self::extract_via_header(packet).unwrap_or("SIP/2.0/UDP pbx:5060".to_string()),
                user, user,
                Self::extract_call_id(packet).unwrap_or_else(|| "12345".to_string()),
                user, client_addr.ip())
    }
    
    async fn handle_invite(&self, packet: &str, client_addr: &SocketAddr) -> String {
        self.log(client_addr, "Processing INVITE request (call simulation)").await;
        
        let to_number = Self::extract_to_number(packet).unwrap_or_else(|| "100".to_string());
        let from_header = Self::extract_from_header(packet).unwrap_or_else(|| "<sip:attacker@unknown>".to_string());
        let via_header = Self::extract_via_header(packet).unwrap_or_else(|| "SIP/2.0/UDP pbx:5060".to_string());
        let call_id = Self::extract_call_id(packet).unwrap_or_else(|| "12345".to_string());
        let cseq = Self::extract_cseq_number(packet).unwrap_or(1);
        
        if self.verbose {
            self.log_verbose(client_addr, "INVITE ATTEMPT",
                &format!("Call from: {}\nCall to: {}\nCall-ID: {}", 
                    from_header, to_number, call_id)).await;
        }
        
        let honeypot_clone = self.clone();
        let client_addr_clone = client_addr.clone();
        let to_number_clone = to_number.clone();
        let from_header_clone = from_header.clone();
        let via_header_clone = via_header.clone();
        let call_id_clone = call_id.clone();
        
        let ring_response = format!("SIP/2.0 180 Ringing\r\n\
                Via: {}\r\n\
                From: {}\r\n\
                To: <sip:{}@pbx>\r\n\
                Call-ID: {}\r\n\
                CSeq: {} INVITE\r\n\
                Content-Length: 0\r\n\r\n",
                via_header,
                from_header,
                to_number,
                call_id,
                cseq);
        
        tokio::spawn(async move {
            time::sleep(time::Duration::from_secs(2)).await;
            
            let ok_response = format!("SIP/2.0 200 OK\r\n\
                    Via: {}\r\n\
                    From: {}\r\n\
                    To: <sip:{}@pbx>\r\n\
                    Call-ID: {}\r\n\
                    CSeq: {} INVITE\r\n\
                    Contact: <sip:{}@{}:5060>\r\n\
                    Content-Type: application/sdp\r\n\
                    Content-Length: 142\r\n\r\n\
                    v=0\r\n\
                    o=user 123456 123456 IN IP4 {}\r\n\
                    s=Call\r\n\
                    c=IN IP4 {}\r\n\
                    t=0 0\r\n\
                    m=audio 1234 RTP/AVP 0 8 101\r\n\
                    a=rtpmap:0 PCMU/8000\r\n\
                    a=rtpmap:8 PCMA/8000\r\n\
                    a=rtpmap:101 telephone-event/8000\r\n",
                    via_header_clone,
                    from_header_clone,
                    to_number_clone,
                    call_id_clone,
                    cseq,
                    to_number_clone, client_addr_clone.ip(),
                    client_addr_clone.ip(),
                    client_addr_clone.ip());
            
            if let Err(e) = honeypot_clone.socket.send_to(ok_response.as_bytes(), client_addr_clone).await {
                honeypot_clone.log(&client_addr_clone, &format!("200 OK send error: {}", e)).await;
            } else {
                honeypot_clone.log(&client_addr_clone, "200 OK sent (answer simulation)").await;
            }
        });
        
        ring_response
    }
    
    async fn handle_options(&self, packet: &str, client_addr: &SocketAddr) -> String {
        self.log(client_addr, "Processing OPTIONS request").await;
        
        format!("SIP/2.0 200 OK\r\n\
                Via: {}\r\n\
                From: {}\r\n\
                To: {}\r\n\
                Call-ID: {}\r\n\
                CSeq: {} OPTIONS\r\n\
                Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REGISTER\r\n\
                Accept: application/sdp\r\n\
                Accept-Encoding: gzip\r\n\
                Accept-Language: en, fr\r\n\
                Content-Length: 0\r\n\r\n",
                Self::extract_via_header(packet).unwrap_or("SIP/2.0/UDP pbx:5060".to_string()),
                Self::extract_from_header(packet).unwrap_or("<sip:attacker@unknown>".to_string()),
                Self::extract_to_header(packet).unwrap_or("<sip:attacker@unknown>".to_string()),
                Self::extract_call_id(packet).unwrap_or_else(|| "12345".to_string()),
                Self::extract_cseq_number(packet).unwrap_or(1))
    }
    
    async fn handle_bye(&self, packet: &str, client_addr: &SocketAddr) -> String {
        self.log(client_addr, "Processing BYE request (call end)").await;
        
        format!("SIP/2.0 200 OK\r\n\
                Via: {}\r\n\
                From: {}\r\n\
                To: {}\r\n\
                Call-ID: {}\r\n\
                CSeq: {} BYE\r\n\
                Content-Length: 0\r\n\r\n",
                Self::extract_via_header(packet).unwrap_or("SIP/2.0/UDP pbx:5060".to_string()),
                Self::extract_from_header(packet).unwrap_or("<sip:attacker@unknown>".to_string()),
                Self::extract_to_header(packet).unwrap_or("<sip:attacker@unknown>".to_string()),
                Self::extract_call_id(packet).unwrap_or_else(|| "12345".to_string()),
                Self::extract_cseq_number(packet).unwrap_or(1))
    }
    
    async fn handle_cancel(&self, _packet: &str, client_addr: &SocketAddr) -> String {
        self.log(client_addr, "Processing CANCEL request").await;
        
        "SIP/2.0 200 OK\r\n\
         Content-Length: 0\r\n\r\n".to_string()
    }
    
    async fn handle_ack(&self, packet: &str, client_addr: &SocketAddr) -> String {
        self.log(client_addr, "Processing ACK request").await;
        
        let call_id = Self::extract_call_id(packet).unwrap_or_else(|| "unknown".to_string());
        self.log(client_addr, &format!("ACK for Call-ID: {}", call_id)).await;
        
        "".to_string()
    }
    
    async fn handle_response(&self, packet: &str, client_addr: &SocketAddr) -> String {
        if let Some(status_code) = Self::extract_status_code(packet) {
            self.log(client_addr, &format!("SIP response received - Code: {}", status_code)).await;
        } else {
            self.log(client_addr, "SIP response received").await;
        }
        
        "".to_string()
    }
    
    async fn handle_unknown(&self, packet: &str, client_addr: &SocketAddr) -> String {
        let first_line = packet.lines().next().unwrap_or("");
        self.log(client_addr, &format!("Unknown SIP method received: {}", first_line)).await;
        
        "SIP/2.0 501 Not Implemented\r\n\
         Content-Length: 0\r\n\r\n".to_string()
    }
    
    // ==================== MÉTHODES D'EXTRACTION D'EN-TÊTES ====================
    
    fn extract_user_from_packet(packet: &str) -> Option<String> {
        let re = Regex::new(r"(?i)From:\s*[^<]*<sip:([^@>]+)").unwrap();
        re.captures(packet)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
    }
    
    fn extract_via_header(packet: &str) -> Option<String> {
        let re = Regex::new(r"(?i)Via:\s*(.*?)\r\n").unwrap();
        re.captures(packet)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
    }
    
    fn extract_call_id(packet: &str) -> Option<String> {
        let re = Regex::new(r"(?i)Call-ID:\s*(.*?)\r\n").unwrap();
        re.captures(packet)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
    }
    
    fn extract_from_header(packet: &str) -> Option<String> {
        let re = Regex::new(r"(?i)From:\s*(.*?)\r\n").unwrap();
        re.captures(packet)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
    }
    
    fn extract_to_header(packet: &str) -> Option<String> {
        let re = Regex::new(r"(?i)To:\s*(.*?)\r\n").unwrap();
        re.captures(packet)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
    }
    
    fn extract_cseq_number(packet: &str) -> Option<u32> {
        let re = Regex::new(r"(?i)CSeq:\s*(\d+)").unwrap();
        re.captures(packet)
            .and_then(|caps| caps.get(1))
            .and_then(|m| m.as_str().parse().ok())
    }
    
    fn extract_to_number(packet: &str) -> Option<String> {
        let re = Regex::new(r"(?i)To:\s*[^<]*<sip:([^@>]+)").unwrap();
        re.captures(packet)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
    }
    
    fn extract_status_code(packet: &str) -> Option<u16> {
        let re = Regex::new(r"SIP/2\.0\s+(\d{3})").unwrap();
        re.captures(packet)
            .and_then(|caps| caps.get(1))
            .and_then(|m| m.as_str().parse().ok())
    }
    
    async fn run(self: Arc<Self>) -> Result<()> {
        let mut buf = [0u8; 65536];
        
        println!("[INFO] Waiting for UDP packets...");
        
        loop {
            match time::timeout(time::Duration::from_secs(5), self.socket.recv_from(&mut buf)).await {
                Ok(Ok((len, client_addr))) => {
                    let packet = buf[..len].to_vec();
                    let honeypot = self.clone();
                    
                    tokio::spawn(async move {
                        honeypot.handle_packet(&packet, client_addr).await;
                    });
                }
                Ok(Err(e)) => {
                    eprintln!("[ERROR] Receive: {}", e);
                }
                Err(_) => {}
            }
        }
    }
}

// ==================== GESTION DU MODE DAEMON ====================

#[cfg(unix)]
fn daemonize() -> Result<()> {
    use daemonize::Daemonize;
    
    println!("[INFO] Starting daemon mode...");
    
    let daemonize = Daemonize::new()
        .pid_file("/tmp/sip-honeypot.pid")
        .chown_pid_file(true)
        .working_directory("/tmp")
        .user("nobody")
        .group("nogroup")
        .umask(0o027);
    
    match daemonize.start() {
        Ok(_) => {
            println!("[INFO] SIP honeypot daemon started successfully");
            Ok(())
        }
        Err(e) => {
            eprintln!("[ERROR] Daemon startup: {}", e);
            Err(anyhow::anyhow!("Failed to start daemon mode"))
        }
    }
}

#[cfg(windows)]
fn daemonize() -> Result<()> {
    println!("[INFO] Daemon mode not fully supported on Windows");
    println!("[INFO] Continuing in background...");
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn daemonize() -> Result<()> {
    println!("[INFO] Daemon mode not supported on this platform");
    Ok(())
}

// ==================== POINT D'ENTRÉE PRINCIPAL ====================

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let opt = Opt::from_args();
    
    // Show version if requested
    if opt.version {
        println!("SIP Honeypot v{}", env!("CARGO_PKG_VERSION"));
        println!("{}", env!("CARGO_PKG_AUTHORS"));
        println!("{}", env!("CARGO_PKG_REPOSITORY"));
        return Ok(());
    }
    
    // Show help if requested
    if opt.help {
        Opt::clap().print_help()?;
        println!();
        return Ok(());
    }
    
    // Show startup information
    println!("==========================================");
    println!("SIP Honeypot v{}", env!("CARGO_PKG_VERSION"));
    println!("{}", env!("CARGO_PKG_AUTHORS"));
    println!("{}", env!("CARGO_PKG_REPOSITORY"));
    println!("==========================================");
    
    // Save log file path before moving opt
    let log_file = opt.log_file.clone();
    let verbose = opt.verbose;
    let raw_display = opt.raw_display;
    
    // Start in daemon mode if requested
    if opt.daemon {
        daemonize()?;
    }
    
    // Create and start honeypot
    let honeypot = Arc::new(SipHoneypot::new(&opt.address, opt.port, log_file, verbose, raw_display).await?);
    
    println!("[INFO] SIP honeypot started");
    println!("[INFO] Address: {}:{}", opt.address, opt.port);
    println!("[INFO] Daemon mode: {}", opt.daemon);
    println!("[INFO] Verbose mode: {}", opt.verbose);
    println!("[INFO] Raw display mode: {}", opt.raw_display);
    println!("[INFO] Waiting for connections...");
    println!("[INFO] Press Ctrl+C to stop");
    
    // Start server
    honeypot.run().await?;
    
    Ok(())
}
