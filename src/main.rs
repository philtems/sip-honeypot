use std::fs::{File, OpenOptions};
use std::io::{Write, BufWriter};
use std::net::SocketAddr;
use std::path::{PathBuf};
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
    version = "0.1.1"
)]
struct Opt {
    /// Run as daemon (requires --log)
    #[structopt(short = "d", long = "daemon")]
    daemon: bool,
    
    /// Listening port (default: 5060)
    #[structopt(short = "p", long = "port", default_value = "5060")]
    port: u16,
    
    /// Log file (MANDATORY in daemon mode)
    #[structopt(short = "l", long = "log", parse(from_os_str))]
    log_file: Option<PathBuf>,
    
    /// Listening address
    #[structopt(short = "a", long = "address", default_value = "0.0.0.0")]
    address: String,
    
    /// Verbose mode - display SIP details
    #[structopt(short = "v", long = "verbose")]
    verbose: bool,
    
    /// Enable raw display (not filtered) - DANGEROUS: can break terminal with control chars
    #[structopt(short = "r", long = "raw")]
    raw_display: bool,
    
    /// PID file (default: /tmp/sip-honeypot.pid)
    #[structopt(long = "pidfile", default_value = "/tmp/sip-honeypot.pid")]
    pid_file: String,
}

// ==================== HONEYPOT PRINCIPAL ====================

#[derive(Clone)]
struct SipHoneypot {
    socket: Arc<UdpSocket>,
    log_writer: Option<Arc<Mutex<BufWriter<File>>>>,
    log_path: Option<PathBuf>,
    verbose: bool,
    raw_display: bool,
    daemon_mode: bool,
}

impl SipHoneypot {
    async fn new(opt: &Opt, daemon_mode: bool) -> Result<Self> {
        let bind_addr = format!("{}:{}", opt.address, opt.port);
        
        // Création du socket UDP
        let socket = UdpSocket::bind(&bind_addr).await
            .with_context(|| format!("Failed to bind to {}", bind_addr))?;
        
        let local_addr = socket.local_addr()?;
        
        // En mode daemon, on n'écrit PAS sur la console
        if !daemon_mode {
            println!("[INFO] SIP honeypot listening on {}", local_addr);
        }
        
        // Gestion du fichier de log
        let log_writer = if let Some(path) = &opt.log_file {
            if let Some(parent) = path.parent() {
                if !parent.exists() {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("Failed to create log directory: {:?}", parent))?;
                }
            }
            
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .with_context(|| format!("Failed to open log file: {:?}", path))?;
            
            // Message dans le log au démarrage
            if daemon_mode {
                // On écrira le message de démarrage plus tard dans run()
            } else {
                println!("[INFO] Logging enabled to: {:?}", path);
            }
            
            Some(Arc::new(Mutex::new(BufWriter::new(file))))
        } else {
            if daemon_mode {
                // En mode daemon, log_file est obligatoire, on ne devrait pas arriver ici
                anyhow::bail!("Daemon mode requires a log file");
            } else {
                println!("[INFO] Logging to stdout only");
            }
            None
        };
        
        Ok(Self {
            socket: Arc::new(socket),
            log_writer,
            log_path: opt.log_file.clone(),
            verbose: opt.verbose,
            raw_display: opt.raw_display,
            daemon_mode,
        })
    }
    
    async fn log(&self, client_addr: &SocketAddr, message: &str) {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        
        let display_message = if self.raw_display {
            message.to_string()
        } else {
            filter_printable_chars(message)
        };
        
        let log_line = format!("{} {} {}\n", timestamp, client_addr, display_message);
        
        // En mode non-daemon, on affiche sur la console
        if !self.daemon_mode {
            print!("{}", log_line);
            let _ = std::io::stdout().flush();
        }
        
        // Toujours écrire dans le fichier de log s'il existe
        if let Some(writer) = &self.log_writer {
            let mut writer = writer.lock().await;
            let file_line = format!("{} {} {}\n", timestamp, client_addr, message);
            if let Err(e) = writer.write_all(file_line.as_bytes()) {
                // En mode daemon, pas de console, on ignore silencieusement
                if !self.daemon_mode {
                    eprintln!("[ERROR] Log write to {:?}: {}", self.log_path, e);
                }
            }
            if let Err(e) = writer.flush() {
                if !self.daemon_mode {
                    eprintln!("[ERROR] Log flush to {:?}: {}", self.log_path, e);
                }
            }
        }
    }
    
    async fn log_verbose(&self, client_addr: &SocketAddr, title: &str, details: &str) {
        if self.verbose {
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
            let separator = "─".repeat(60);
            
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
            
            // Afficher seulement en mode non-daemon
            if !self.daemon_mode {
                print!("{}", verbose_log);
                let _ = std::io::stdout().flush();
            }
            
            // Toujours écrire dans le fichier de log
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
                let _ = writer.write_all(file_log.as_bytes());
                let _ = writer.flush();
            }
        }
    }
    
    async fn handle_packet(&self, buf: &[u8], client_addr: SocketAddr) {
        let packet_str = String::from_utf8_lossy(buf);
        
        if self.verbose {
            self.log_verbose(&client_addr, "RAW PACKET", &packet_str).await;
        }
        
        let check_packet = if self.raw_display {
            packet_str.to_string()
        } else {
            filter_printable_chars(&packet_str)
        };
        
        if Self::is_sip_packet(&check_packet) {
            self.log(&client_addr, &format!("SIP packet received ({} bytes)", buf.len())).await;
            
            if self.verbose {
                self.extract_and_log_auth_info(&client_addr, &packet_str).await;
            }
            
            if let Some(method) = Self::parse_sip_method(&check_packet) {
                self.log(&client_addr, &format!("SIP method detected: {}", method)).await;
                
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
        
        if let Some(user) = Self::extract_user_from_packet(packet) {
            auth_info.push(format!("User/Phone: {}", user));
        }
        
        if let Some(to) = Self::extract_to_number(packet) {
            auth_info.push(format!("To number: {}", to));
        }
        
        if let Some(from) = Self::extract_from_user(packet) {
            auth_info.push(format!("From user: {}", from));
        }
        
        if let Some(auth_header) = Self::extract_authorization_header(packet) {
            auth_info.push(format!("Authorization: {}", auth_header));
            
            if let Some(username) = Self::extract_auth_username(packet) {
                auth_info.push(format!("Auth Username: {}", username));
            }
            
            if let Some(realm) = Self::extract_auth_realm(packet) {
                auth_info.push(format!("Auth Realm: {}", realm));
            }
            
            if let Some(response) = Self::extract_auth_response(packet) {
                auth_info.push(format!("Auth Response (hash): {}", response));
            }
        }
        
        if let Some(user_agent) = Self::extract_user_agent(packet) {
            auth_info.push(format!("User-Agent: {}", user_agent));
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
    
    fn extract_auth_response(packet: &str) -> Option<String> {
        let re = Regex::new("(?i)response=\"?([^\",]+)\"?").unwrap();
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
    
    fn extract_status_code(packet: &str) -> Option<u16> {
        let re = Regex::new(r"SIP/2\.0\s+(\d{3})").unwrap();
        re.captures(packet)
            .and_then(|caps| caps.get(1))
            .and_then(|m| m.as_str().parse().ok())
    }
    
    fn extract_user_from_packet(packet: &str) -> Option<String> {
        let re = Regex::new(r"(?i)From:\s*[^<]*<sip:([^@>]+)").unwrap();
        re.captures(packet)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
    }
    
    async fn run(self: Arc<Self>) -> Result<()> {
        let mut buf = [0u8; 65536];
        
        // Message de démarrage dans le log
        if self.daemon_mode {
            if let Some(writer) = &self.log_writer {
                let mut writer = writer.lock().await;
                let _ = writeln!(writer, 
                    "=== SIP Honeypot daemon started at PID {} ===", 
                    std::process::id());
                let _ = writeln!(writer, 
                    "=== Listening on {}:{} ===", 
                    self.socket.local_addr()?.ip(),
                    self.socket.local_addr()?.port());
                let _ = writer.flush();
            }
        } else {
            println!("[INFO] Waiting for UDP packets...");
            println!("[INFO] Listening on: {}", self.socket.local_addr()?);
        }
        
        let mut packet_count = 0;
        
        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, client_addr)) => {
                    packet_count += 1;
                    let packet = buf[..len].to_vec();
                    let honeypot = self.clone();
                    
                    if packet_count <= 5 && self.verbose && !self.daemon_mode {
                        println!("[DEBUG] Packet #{} from {} ({} bytes)", 
                                 packet_count, client_addr, len);
                    }
                    
                    tokio::spawn(async move {
                        honeypot.handle_packet(&packet, client_addr).await;
                    });
                }
                Err(e) => {
                    // En mode daemon, pas de console
                    if !self.daemon_mode {
                        eprintln!("[ERROR] Receive error: {}", e);
                    }
                    
                    // Logger l'erreur dans le fichier si disponible
                    if let Some(writer) = &self.log_writer {
                        let mut writer = writer.lock().await;
                        let _ = writeln!(writer, 
                            "[ERROR] Receive error: {}", e);
                    }
                    
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }
    }
}

// ==================== POINT D'ENTRÉE PRINCIPAL ====================

#[cfg(unix)]
fn redirect_stdout_stderr_to_dev_null() {
    use std::os::unix::io::AsRawFd;
    
    // Ouvrir /dev/null
    if let Ok(null) = std::fs::File::open("/dev/null") {
        let null_fd = null.as_raw_fd();
        
        // Rediriger stdout et stderr vers /dev/null
        unsafe {
            libc::dup2(null_fd, libc::STDOUT_FILENO);
            libc::dup2(null_fd, libc::STDERR_FILENO);
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::from_args();
    
    // Vérification : en mode daemon, le fichier de log est OBLIGATOIRE
    if opt.daemon && opt.log_file.is_none() {
        eprintln!("[ERROR] Daemon mode requires a log file (-l/--log)");
        std::process::exit(1);
    }
    
    // Afficher le banner (uniquement en mode non-daemon)
    if !opt.daemon {
        println!("==========================================");
        println!("SIP Honeypot v{}", env!("CARGO_PKG_VERSION"));
        println!("==========================================");
    }
    
    // Vérifier le port
    if opt.port < 1024 && !opt.daemon {
        eprintln!("[WARNING] Port {} is privileged. You might need root to bind.", opt.port);
    }
    
    // Afficher les infos utilisateur (uniquement en mode non-daemon)
    if !opt.daemon {
        eprintln!("[INFO] Starting as user: {}", 
                  std::env::var("USER").unwrap_or_else(|_| "unknown".to_string()));
        eprintln!("[INFO] PID: {}", std::process::id());
        eprintln!("[INFO] Working directory: {:?}", std::env::current_dir().unwrap());
    }
    
    // Vérifier/Créer le répertoire pour le fichier de log
    if let Some(log_path) = &opt.log_file {
        if let Some(parent) = log_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
                if !opt.daemon {
                    eprintln!("[INFO] Created log directory: {:?}", parent);
                }
            }
        }
    }
    
    // === MODE DAEMON : AUTO-RELANCE AVEC NOHUP ===
    if opt.daemon {
        // Vérifier si on est déjà dans le processus fils (lancé par nohup)
        let is_child = std::env::var("SIP_HONEYPOT_CHILD").unwrap_or_default() == "1";
        
        if !is_child {
            // PREMIÈRE EXÉCUTION : on se relance avec nohup
            let exe = std::env::current_exe()?;
            let args: Vec<String> = std::env::args().collect();
            
            // Construire la commande nohup
            let mut cmd = std::process::Command::new("nohup");
            
            // Rediriger stdout et stderr vers /dev/null pour éviter nohup.out
            cmd.stdout(std::process::Stdio::null());
            cmd.stderr(std::process::Stdio::null());
            
            cmd.arg(&exe);
            
            // Passer tous les arguments sauf -d/--daemon
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "-d" | "--daemon" => {
                        // Sauter l'option daemon
                        i += 1;
                    }
                    arg if arg.starts_with("-d") && arg.len() > 2 => {
                        // Options combinées comme -dv
                        let remaining = &arg[2..]; // Récupère "v" après "-d"
                        if !remaining.is_empty() {
                            // Ajouter un tiret pour l'option (ex: -v)
                            cmd.arg(format!("-{}", remaining));
                        }
                        i += 1;
                    }
                    _ => {
                        cmd.arg(&args[i]);
                        i += 1;
                    }
                }
            }
            
            // Ajouter une variable d'environnement pour identifier le processus fils
            cmd.env("SIP_HONEYPOT_CHILD", "1");
            
            // Afficher les informations de démarrage (sur la console du parent)
            println!("==========================================");
            println!("SIP Honeypot v{}", env!("CARGO_PKG_VERSION"));
            println!("==========================================");
            println!("[INFO] Starting daemon mode...");
            println!("[INFO] Log file: {:?}", opt.log_file);
            println!("[INFO] nohup output redirected to /dev/null");
            
            // Lancer le processus
            match cmd.spawn() {
                Ok(child) => {
                    // Écrire le PID dans le fichier
                    std::fs::write(&opt.pid_file, child.id().to_string())?;
                    
                    println!("[INFO] Daemon started with PID: {}", child.id());
                    println!("[INFO] Parent process exiting");
                    
                    // Le parent se termine immédiatement
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("[ERROR] Failed to start daemon: {}", e);
                    std::process::exit(1);
                }
            }
        } else {
            // PROCESSUS FILS (sous nohup)
            // On est dans le processus nohup - rediriger stdout/stderr vers /dev/null
            // pour être SÛR que rien n'aille dans nohup.out
            redirect_stdout_stderr_to_dev_null();
        }
    }
    
    // === MODE NORMAL OU PROCESSUS FILS (DAEMON) ===
    let is_daemon = opt.daemon; // true seulement dans le processus fils
    
    // Créer l'instance du honeypot
    let honeypot = Arc::new(SipHoneypot::new(&opt, is_daemon).await?);
    
    // Message de démarrage (console en mode normal, fichier log en mode daemon)
    if !is_daemon {
        println!("[INFO] SIP honeypot started in foreground");
        println!("[INFO] PID: {}", std::process::id());
        println!("[INFO] Address: {}:{}", opt.address, opt.port);
        println!("[INFO] Waiting for UDP packets...");
        println!("[INFO] Press Ctrl+C to stop");
    }
    
    // Lancer la boucle principale
    honeypot.run().await?;
    
    Ok(())
}

