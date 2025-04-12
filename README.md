# Security Scripts Collection

<a name="readme-top"></a>

<div align="center">
  <h3>Windows Forensics ANALYZER & SOC Analyst CHECKER</h3>
  <p>
    A collection of advanced security analysis tools for digital forensics and SOC team testing.
    <br />
    Developed by Emmanuel SHYIRAMBERE under the guidance of Mr. Dominic HARELIMANA and David Shiffman
  </p>
</div>

## Table of Contents

- [About The Projects](#about-the-projects)
  - [ANALYZER Key Features](#analyzer-key-features)
  - [CHECKER Key Features](#checker-key-features)
  - [Built With](#built-with)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Usage](#usage)
- [Project Structure](#project-structure)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [Contact](#contact)

## About The Projects

This repository contains powerful security tools developed during ThinkCyber Educational Pilot Program, a collaborative initiative with the Ministry of Education in Rwanda and University of Rwanda. This program represents a crucial step in my journey towards becoming proficient in cybersecurity, equipping me with the skills necessary to navigate and protect digital environments in today’s challenging landscape:

### ANALYZER - Windows Forensics Tool (NX212)
`ANALYZER` is an advanced digital forensics tool that combines memory analysis with file carving techniques to streamline forensic investigations while maintaining strict evidentiary standards.

#### ANALYZER Key Features

1. **Comprehensive Memory Analysis**
   - Automatic memory profile detection
   - Volatility Framework integration
   - Process listing, network connection analysis, and registry examination

2. **Advanced File Carving**
   - Multi-layered data recovery approach
   - Signature-based analysis with Foremost
   - Structural analysis via Binwalk

3. **Pattern Recognition Engine**
   - Deep scanning for sensitive information
   - Credential patterns, network artifacts, system indicators
   - Customizable pattern dictionaries

4. **Automated Reporting**
   - Court-ready report generation
   - Multiple output formats (text, HTML, PDF)
   - Analysis methodology and chain of custody documentation

### CHECKER - SOC Analyst Tool (NX220)
`CHECKER` is a security testing system designed to enhance SOC team capabilities through controlled attack simulations with comprehensive logging.

#### CHECKER Key Features

1. **Network Discovery**
   - Comprehensive network scanning with Nmap
   - Flexible target selection options
   - Clear presentation of available hosts

2. **Attack Simulations**
   - Port scanning mechanism
   - Controlled DoS testing with hping3
   - ARP spoofing assessment

3. **Comprehensive Logging**
   - Detailed audit trail of all activities
   - Timestamped attack records
   - Standardized format for easy analysis

4. **Safety Controls**
   - Root privilege verification
   - Input validation
   - Careful attack parameter control

### Built With

- **Core Technologies**
  - Bash scripting
  - Volatility Framework
  - Bulk Extractor
  - Foremost
  - Binwalk
  - Nmap
  - hping3
  - dsniff

- **Supporting Tools**
  - grep, awk, sed for text processing
  - date, du, file for system information
  - zip for report packaging

## Getting Started

### Prerequisites

- Linux environment (Kali Linux recommended)
- Root privileges
- Basic dependencies:
  ```bash
  sudo apt-get install nmap hping3 dsniff ipcalc bulk-extractor foremost binwalk volatility


### Installation

1. Clone the repository

```bash
git clone https://github.com/EmmanuelSHYIRAMBERE/Security_Scripts.git
cd Security_Scripts
```

2. Make scripts executable:

```bash
chmod +x RW-University-II.s7.nx212.sh RW-University-II.s7.nx215.sh
```


### Usage
## ANALYZER (Windows Forensics)
```bash
sudo ./RW-University-II.s7.nx212.sh
```

The script will:

- Perform pre-flight checks (OS detection, root verification)

- Guide you through file selection

- Conduct memory and file analysis

- Generate comprehensive reports


## CHECKER (SOC Analyst)
```bash
sudo ./RW-University-II.s7.nx215.sh
```

The script will:

- Check dependencies

- Perform network discovery

- Present attack simulation options


## Project Structure

```
Security_Scripts/
├── RW-University-II.s7.nx212.sh          # ANALYZER main script
├── RW-University-II.s7.nx212.pdf         # ANALYZER documentation
├── RW-University-II.s7.nx215.sh          # CHECKER main script
├── RW-University-II.s7.nx215.pdf         # CHECKER documentation
└── README.md                             # This document
```


## Key technical aspects covered

- System architecture
- Memory analysis implementation
- File carving mechanisms
- Network discovery processes
- Attack simulation methodologies
- Error handling implementations


## Security Considerations
Both tools implement strict security protocols:

### 1. Privilege Management
- Root privileges requested only when necessary
- Privilege escalation verification

### 2. Evidence Integrity
- Cryptographic verification of tool integrity
- Isolated analysis environments
- Secure temporary file handling

### 3. Audit Trails
- Detailed logging of all operations
- Timestamped activities
- Chain of custody documentation

### 4. Safety Controls
- Input validation
- Parameter sanitization
- Graceful degradation features

## Contributing

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some amazing feature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Contact

Emmanuel SHYIRAMBERE - [LinkedIn Profile](https://www.linkedin.com/in/emashyirambere)

<p align="right">(<a href="#readme-top">back to top</a>)</p>
