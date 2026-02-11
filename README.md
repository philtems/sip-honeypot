SIP HONEYPOT

A SIP honeypot for detecting and analyzing SIP attacks on VoIP networks.
This tool listens for SIP requests and simulates a legitimate SIP server
to capture attack patterns, credential attempts, and other malicious activities.

AUTHOR

Philippe TEMESI (2026)
https://www.tems.be


DESCRIPTION

SIP Honeypot simulates a SIP server (UDP port 5060 by default) and responds
to common SIP methods including REGISTER, INVITE, OPTIONS, BYE, CANCEL, and ACK.
It logs all incoming packets and can optionally record detailed information
about authentication attempts, phone numbers, user agents, and other SIP details.

The honeypot is designed to be lightweight, run as a daemon on Unix systems,
and provide valuable intelligence about SIP-based attacks on your network.

FEATURES

    SIP protocol simulation (REGISTER, INVITE, OPTIONS, BYE, CANCEL, ACK)

    Configurable listening address and port

    File logging with timestamps

    Daemon mode for Unix systems (Linux, BSD, macOS)

    Verbose mode for detailed SIP inspection

    Automatic extraction of credentials and phone numbers

    Multi-threaded packet handling with Tokio

    Response simulation (180 Ringing, 200 OK with SDP for INVITE)

REQUIREMENTS

    Rust 1.70 or higher

    Cargo package manager

    Linux, BSD, macOS, or Windows (daemon mode only on Unix)

COMPILATION

    Clone the repository or download the source files:
    git clone https://github.com/philtems/sip-honeypot.git
    cd sip-honeypot

    Compile in release mode:
    cargo build --release

    The binary will be located at:
    target/release/sip-honeypot

    Optional: Install system-wide:
    sudo cp target/release/sip-honeypot /usr/local/bin/

QUICK START

Basic usage with default settings:
./sip-honeypot

Enable logging to a file:
./sip-honeypot -l /var/log/sip-honeypot.log

Enable verbose mode to see SIP details:
./sip-honeypot -v

Run as daemon in background:
./sip-honeypot -d

Listen on specific IP and port:
./sip-honeypot -a 192.168.1.100 -p 5060

Full featured example:
./sip-honeypot -d -v -l /var/log/sip-honeypot.log -a 0.0.0.0 -p 5060

COMMAND LINE OPTIONS

-d, --daemon Run as daemon (Unix systems only)
-p, --port <port> Listening port (default: 5060)
-l, --log <file> Log file path (optional)
-a, --address <ip> Listening address (default: 0.0.0.0)
-v, --verbose Verbose mode - display SIP details including phone numbers,
login attempts, passwords, and authentication headers
-h, --help Show help information
-V, --version Show version information

OUTPUT AND LOGGING

All output includes timestamp and client IP address:

2026-02-11 14:23:45.123 192.168.1.10:5060 SIP packet received (512 bytes)
2026-02-11 14:23:45.124 192.168.1.10:5060 SIP method detected: REGISTER
2026-02-11 14:23:45.125 192.168.1.10:5060 Response sent (256 bytes)

Verbose mode adds detailed sections:

2026-02-11 14:23:45.123 VERBOSE: 192.168.1.10:5060 SIP DETAILS

User/Phone: john.doe
From user: john.doe
Authorization: Digest username="john.doe", realm="asterisk", nonce="123456", uri="sip:pbx", response="abcdef123456"
User-Agent: Zoiper/5.5.10
Contact: sip:john.doe@192.168.1.10:5060

RESPONSES

    REGISTER -> 200 OK (simulates successful registration)

    INVITE -> 180 Ringing immediately, then 200 OK with SDP after 2 seconds

    OPTIONS -> 200 OK with capabilities

    BYE -> 200 OK

    CANCEL -> 200 OK

    ACK -> No response (acknowledgment only)

    Unknown -> 501 Not Implemented

DAEMON MODE (UNIX ONLY)

When running with -d flag, the honeypot will:

    Fork to background

    Create PID file: /tmp/sip-honeypot.pid

    Run as user: nobody

    Run as group: nogroup

    Set umask: 027

To stop the daemon:
kill $(cat /tmp/sip-honeypot.pid)

EXAMPLES

    Capture SIP scanning activities:
    sudo ./sip-honeypot -v -l scan_log.txt

    Permanent installation as service:
    sudo ./sip-honeypot -d -v -l /var/log/sip-honeypot.log

    Testing with sipvicious:
    ./svmap -p 5060 192.168.1.0/24
    ./svcrack -u 100 -d dictionary.txt 192.168.1.100

    Testing with legitimate SIP client:
    Configure your softphone to register to your honeypot IP
    Observe credentials captured in verbose mode

SECURITY NOTES

    This tool is for security research and network defense

    Do not deploy on production networks without proper authorization

    Captured credentials should be handled securely

    The honeypot does NOT forward calls or provide actual VoIP service

    Use firewall rules to restrict access if needed

TROUBLESHOOTING

Problem: "Failed to bind to 0.0.0.0:5060"
Solution: Port 5060 is already in use. Change port with -p or stop the other service.

Problem: "Failed to open log file: Permission denied"
Solution: Ensure you have write permissions for the log directory.

Problem: Daemon mode fails on non-Unix system
Solution: Remove -d flag on Windows or other platforms.

Problem: No packets received
Solution: Check firewall settings, network connectivity, and ensure SIP clients are sending to correct IP.

FILES

sip-honeypot Main executable
/tmp/sip-honeypot.pid PID file (daemon mode)
/var/log/sip-honeypot.log Example log file location

DEPENDENCIES

tokio - Async runtime
structopt - Command line parsing
chrono - Timestamp formatting
lazy_static - Static regex compilation
regex - SIP header parsing
anyhow - Error handling
daemonize - Unix daemon mode (Unix only)
libc - System calls (Unix only)

BUILD FROM SOURCE WITH DEPENDENCIES

cargo build --release
cargo build --release --target x86_64-unknown-linux-gnu
cargo build --release --target x86_64-pc-windows-gnu

CROSS-COMPILATION

For Windows from Linux:
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu

For ARM (Raspberry Pi):
rustup target add armv7-unknown-linux-gnueabihf
cargo build --release --target armv7-unknown-linux-gnueabihf


SUPPORT

For issues, questions, or contributions:
https://www.tems.be
https://github.com/philtems/sip-honeypot

DISCLAIMER

This software is provided "as is" without warranty of any kind.
Use at your own risk. The author is not responsible for any misuse
or damage caused by this program. Always ensure you have proper
authorization before testing or deploying security tools.

ACKNOWLEDGMENTS

    Tokio team for the async runtime

    Rust community for excellent crates

    SIP protocol specification (RFC 3261)
