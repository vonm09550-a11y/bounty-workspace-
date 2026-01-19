# HexStrike AI MCP Tool - Setup Complete

## Installation Location
```
/home/user/bounty-workspace-/hexstrike-ai/
```

## Quick Start

### 1. Start the Server
```bash
cd /home/user/bounty-workspace-/hexstrike-ai
source hexstrike-env/bin/activate
python3 hexstrike_server.py
# For debug mode: python3 hexstrike_server.py --debug
```

### 2. Server Endpoints
- **Health Check**: `http://127.0.0.1:8888/health`
- **API Base**: `http://127.0.0.1:8888/api/`

### 3. MCP Configuration
Copy `hexstrike-mcp-config.json` to your Claude Desktop config:
- **Linux**: `~/.config/Claude/claude_desktop_config.json`
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

---

## Available Tools (150+)

### Network & Reconnaissance (25+)
| Tool | Function | MCP Tool Name |
|------|----------|---------------|
| Nmap | Port scanning & service detection | `nmap_scan`, `nmap_advanced_scan` |
| Rustscan | Ultra-fast port scanning | `rustscan_fast_scan` |
| Masscan | High-speed Internet-scale scanning | `masscan_high_speed` |
| AutoRecon | Automated reconnaissance | `autorecon_comprehensive` |
| Amass | Subdomain enumeration | `amass_scan` |
| Subfinder | Passive subdomain enumeration | `subfinder_scan` |
| nbtscan | NetBIOS name scanning | `nbtscan_netbios` |
| arp-scan | Network discovery | `arp_scan_discovery` |
| Responder | Credential harvesting | `responder_credential_harvest` |

### Web Application Security (40+)
| Tool | Function | MCP Tool Name |
|------|----------|---------------|
| Gobuster | Directory brute forcing | `gobuster_scan` |
| Feroxbuster | Recursive content discovery | `feroxbuster_scan` |
| Dirsearch | Directory discovery | `dirsearch_scan` |
| FFuf | Web fuzzing | `ffuf_scan` |
| Dirb | Directory brute forcing | `dirb_scan` |
| Nuclei | Vulnerability scanning | `nuclei_scan` |
| Nikto | Web vulnerability scanner | `nikto_scan` |
| SQLMap | SQL injection testing | `sqlmap_scan` |
| WPScan | WordPress scanning | `wpscan_analyze` |
| Katana | Web crawling | `katana_crawl` |
| Gau | URL discovery | `gau_discovery` |
| Waybackurls | Historical URL discovery | `waybackurls_discovery` |
| Arjun | Parameter discovery | `arjun_parameter_discovery` |
| ParamSpider | Parameter mining | `paramspider_mining` |
| x8 | Hidden parameter discovery | `x8_parameter_discovery` |
| Dalfox | XSS vulnerability scanning | `dalfox_xss_scan` |
| Jaeles | Custom signature scanning | `jaeles_vulnerability_scan` |
| httpx | HTTP probing | `httpx_probe` |
| XSSer | XSS testing | `xsser_scan` |
| Wfuzz | Web application fuzzing | `wfuzz_scan` |
| DotDotPwn | Directory traversal | `dotdotpwn_scan` |
| Burp Suite | Web security testing | `burpsuite_scan` |
| OWASP ZAP | Web application scanner | `zap_scan` |
| Hakrawler | Web endpoint discovery | `hakrawler_crawl` |

### Authentication & Password Cracking (12+)
| Tool | Function | MCP Tool Name |
|------|----------|---------------|
| Hydra | Password brute forcing | `hydra_attack` |
| John the Ripper | Password cracking | `john_crack` |
| Hashcat | Advanced password cracking | `hashcat_crack` |

### SMB & Windows Enumeration
| Tool | Function | MCP Tool Name |
|------|----------|---------------|
| Enum4linux | SMB enumeration | `enum4linux_scan` |
| Enum4linux-ng | Advanced SMB enumeration | `enum4linux_ng_advanced` |
| SMBMap | SMB share enumeration | `smbmap_scan` |
| NetExec | Network enumeration | `netexec_scan` |
| rpcclient | RPC enumeration | `rpcclient_enumeration` |

### Binary Analysis & Reverse Engineering (25+)
| Tool | Function | MCP Tool Name |
|------|----------|---------------|
| GDB | Debugging | `gdb_analyze`, `gdb_peda_debug` |
| Radare2 | Reverse engineering | `radare2_analyze` |
| Ghidra | Binary analysis | `ghidra_analysis` |
| Binwalk | Firmware analysis | `binwalk_analyze` |
| ROPgadget | ROP gadget search | `ropgadget_search` |
| Ropper | Advanced gadget search | `ropper_gadget_search` |
| Checksec | Security feature analysis | `checksec_analyze` |
| Strings | String extraction | `strings_extract` |
| Objdump | Binary analysis | `objdump_analyze` |
| xxd | Hex dump | `xxd_hexdump` |
| Pwntools | Exploit development | `pwntools_exploit` |
| one_gadget | One-shot RCE gadgets | `one_gadget_search` |
| angr | Symbolic execution | `angr_symbolic_execution` |
| libc-database | Libc identification | `libc_database_lookup` |
| pwninit | CTF setup | `pwninit_setup` |

### Cloud & Container Security (20+)
| Tool | Function | MCP Tool Name |
|------|----------|---------------|
| Prowler | AWS/Azure/GCP assessment | `prowler_scan` |
| Scout Suite | Multi-cloud security | `scout_suite_assessment` |
| CloudMapper | AWS network analysis | `cloudmapper_analysis` |
| Pacu | AWS exploitation | `pacu_exploitation` |
| Trivy | Container vulnerability scanning | `trivy_scan` |
| Kube-Hunter | Kubernetes pentesting | `kube_hunter_scan` |
| Kube-Bench | CIS benchmark | `kube_bench_cis` |
| Docker Bench | Docker security | `docker_bench_security_scan` |
| Clair | Container vulnerability | `clair_vulnerability_scan` |
| Falco | Runtime monitoring | `falco_runtime_monitoring` |
| Checkov | IaC scanning | `checkov_iac_scan` |
| Terrascan | IaC security | `terrascan_iac_scan` |

### CTF & Forensics (20+)
| Tool | Function | MCP Tool Name |
|------|----------|---------------|
| Volatility | Memory forensics | `volatility_analyze` |
| Volatility3 | Advanced memory forensics | `volatility3_analyze` |
| Foremost | File carving | `foremost_carving` |
| Steghide | Steganography | `steghide_analysis` |
| ExifTool | Metadata extraction | `exiftool_extract` |
| HashPump | Hash length extension | `hashpump_attack` |

### Payload Generation
| Tool | Function | MCP Tool Name |
|------|----------|---------------|
| MSFVenom | Payload generation | `msfvenom_generate` |
| Metasploit | Exploitation framework | `metasploit_run` |

### AI-Powered Features
| Tool | Function | MCP Tool Name |
|------|----------|---------------|
| AI Payload Generator | Context-aware payloads | `ai_generate_payload` |
| AI Payload Tester | Payload testing | `ai_test_payload` |
| AI Attack Suite | Comprehensive attack generation | `ai_generate_attack_suite` |

### API Testing
| Tool | Function | MCP Tool Name |
|------|----------|---------------|
| API Fuzzer | Endpoint fuzzing | `api_fuzzer` |
| GraphQL Scanner | GraphQL security | `graphql_scanner` |
| JWT Analyzer | JWT vulnerability testing | `jwt_analyzer` |
| API Schema Analyzer | Schema security analysis | `api_schema_analyzer` |
| Comprehensive API Audit | Full API assessment | `comprehensive_api_audit` |

### File Operations
| Function | MCP Tool Name |
|----------|---------------|
| Create file | `create_file` |
| Modify file | `modify_file` |
| Delete file | `delete_file` |
| List files | `list_files` |
| Generate payload | `generate_payload` |

### Python Environment
| Function | MCP Tool Name |
|----------|---------------|
| Install package | `install_python_package` |
| Execute script | `execute_python_script` |

---

## Usage Examples

### Basic Nmap Scan
```
nmap_scan(target="192.168.1.1", scan_type="-sV", ports="22,80,443")
```

### Directory Brute Force
```
gobuster_scan(url="http://target.com", mode="dir", wordlist="/usr/share/wordlists/dirb/common.txt")
```

### Vulnerability Scan
```
nuclei_scan(target="http://target.com", severity="critical,high")
```

### SQL Injection Test
```
sqlmap_scan(url="http://target.com/page.php?id=1")
```

### Subdomain Enumeration
```
subfinder_scan(domain="target.com", all_sources=True)
```

### AI Payload Generation
```
ai_generate_payload(attack_type="xss", complexity="advanced", technology="php")
```

---

## Requirements for External Tools

The MCP server provides the interface, but you need the actual security tools installed:

### Kali Linux (Recommended)
Most tools come pre-installed on Kali Linux 2024.1+

### Manual Installation
```bash
# Network tools
apt install nmap masscan rustscan

# Web tools
apt install gobuster feroxbuster dirsearch ffuf dirb nikto sqlmap

# Password tools
apt install hydra john hashcat

# SMB tools
apt install enum4linux smbmap

# Binary tools
apt install gdb radare2 binwalk checksec pwntools

# Cloud tools
pip install prowler scout-suite trivy
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        AI Agent (Claude)                        │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    hexstrike_mcp.py (MCP Client)                │
│                  FastMCP Integration Layer                       │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                  hexstrike_server.py (API Server)               │
│              Flask REST API on http://127.0.0.1:8888            │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │ Tool Manager │  │ Cache Engine │  │ Decision Engine      │   │
│  │ (150+ tools) │  │ (LRU Cache)  │  │ (AI-powered routing) │   │
│  └──────────────┘  └──────────────┘  └──────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              Process Pool & Error Recovery                │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                   External Security Tools                        │
│     (nmap, gobuster, nuclei, sqlmap, hydra, etc.)               │
└─────────────────────────────────────────────────────────────────┘
```

---

## Server Configuration

Environment variables:
- `HEXSTRIKE_PORT`: Server port (default: 8888)
- `HEXSTRIKE_HOST`: Server host (default: 127.0.0.1)

Command line:
```bash
python3 hexstrike_server.py --debug  # Debug mode
python3 hexstrike_server.py          # Normal mode
```
