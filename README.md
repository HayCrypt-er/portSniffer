# portSniff

A lightweight port packet sniffer automation utility written in C.

This tool acts as a wrapper around `arpspoof` to simplify authorized network testing workflows in controlled lab environments.

**Author:** HayCrypt-er

---

##  Features

- Automates ARP spoofing setup
- Validates input parameters
- Requires minimal user interaction
- Lightweight and fast
- Designed for educational and security research purposes

---

##  Requirements

- Linux (Debian-based distributions recommended)
- Root privileges
- `dsniff` package (provides `arpspoof`)
- GCC compiler

The installer will automatically install required dependencies.

---

##  Installation

Clone the repository:

```bash
git clone https://github.com/HayCrypt-er/portSniffer.git
cd portSniffer
```

Run the installer:

```bash
sudo ./install.sh
```

This will:

- Install required dependency (dsniff) if missing
- Install the tool system-wide
- Make it executable from anywhere

##  Usage

After installation:

```bash
sudo portSniffer -v <target_ip> -o <logs_directory> [-p <port (default 443)>]
```

Example:

```bash
sudo portSniffer -v 192.168.1.10 -o /home 
```

##  Legal Disclaimer

This software is developed strictly for educational purposes and authorized security testing.

By using this tool, you agree that:

- You have explicit authorization to test the target network
- You understand and comply with local, national, and international cybersecurity laws
- You accept full responsibility for any consequences resulting from its use

The author is not responsible for misuse, damages, or illegal activities performed using this software.
