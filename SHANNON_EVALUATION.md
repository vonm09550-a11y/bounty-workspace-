# Shannon - Autonomous AI Pentester Evaluation

## What is Shannon?

Shannon (by KeygraphHQ) is a fully autonomous AI penetration testing framework that
identifies and exploits real vulnerabilities in web applications. It uses Claude Agent SDK
under the hood to orchestrate multiple specialized AI agents that perform code-aware
dynamic testing — combining source code analysis with live runtime exploitation.

**Key claim:** 96.15% success rate on the XBOW benchmark (hint-free, source-aware).

**License:** AGPL-3.0 (Shannon Lite), Commercial (Shannon Pro)

## Architecture Overview

### Five-Phase Pipeline (Temporal orchestrated)

```
Phase 1: Pre-Recon     → External tool scans (nmap, subfinder, whatweb) + code analysis
Phase 2: Recon         → Attack surface mapping from findings
Phase 3: Vuln Analysis → 5 parallel agents: injection, XSS, auth, authz, SSRF
Phase 4: Exploitation  → 5 parallel agents (only if vulns found in Phase 3)
Phase 5: Reporting     → Executive-level report with PoC evidence
```

### Core Components

| Component | Purpose |
|---|---|
| `shannon` CLI | Bash entrypoint - starts Docker Compose stack |
| `docker-compose.yml` | Temporal server + Shannon worker containers |
| `src/temporal/workflows.ts` | Durable workflow orchestration via Temporal |
| `src/temporal/activities.ts` | Activity implementations with heartbeats |
| `src/ai/claude-executor.ts` | Claude Agent SDK integration (model: claude-sonnet-4-5) |
| `src/session-manager.ts` | Agent definitions, execution order, parallel groups |
| `src/config-parser.ts` | YAML config with JSON Schema validation |
| `mcp-server/` | Shannon helper MCP server (TOTP generation, etc.) |
| `prompts/` | Specialized prompt templates per testing phase |

### 13 Specialized Agents

1. `pre-recon` - External tool scans + source code analysis
2. `recon` - Attack surface mapping
3. `injection-vuln` / `injection-exploit` - SQL/command injection
4. `xss-vuln` / `xss-exploit` - Cross-site scripting
5. `auth-vuln` / `auth-exploit` - Authentication bypasses
6. `authz-vuln` / `authz-exploit` - Authorization flaws
7. `ssrf-vuln` / `ssrf-exploit` - Server-side request forgery
8. `report` - Executive report generation

### Security Tools Bundled in Docker Image

- **nmap** - Network port scanning
- **subfinder** - Subdomain discovery
- **whatweb** - Web technology fingerprinting
- **schemathesis** - API schema testing
- **Playwright/Chromium** - Browser automation for web testing

## How to Run

### Prerequisites

- Docker (with Docker Compose)
- Anthropic API key (or Claude Code OAuth token)

### Quick Start

```bash
cd shannon

# 1. Configure credentials
cp .env.example .env
# Edit .env: set ANTHROPIC_API_KEY=your-key

# 2. Run against a target (white-box: needs source code)
./shannon start URL=https://target-app.com REPO=/path/to/target/source

# 3. Monitor progress
./shannon logs ID=<workflow-id>
# Or open Temporal Web UI: http://localhost:8233

# 4. Stop
./shannon stop
```

### Pipeline Testing Mode (faster iteration)

```bash
./shannon start URL=https://target.com REPO=/path/to/repo PIPELINE_TESTING=true
```

### Custom Config (for authenticated targets)

```bash
./shannon start URL=https://target.com REPO=/path/to/repo CONFIG=./configs/my-config.yaml
```

## Relevance to Bounty Program

### Strengths

- **White-box testing** - Combines source code analysis with runtime exploitation
- **Zero false positives policy** - "No exploit, no report" approach
- **Parallel execution** - 5 concurrent vulnerability/exploitation agents
- **Crash recovery** - Temporal ensures workflows resume after failures
- **Professional reports** - Generates executive-level findings with reproducible PoCs
- **Authenticated testing** - Supports form login, SSO, API keys, TOTP/2FA
- **Configurable scope** - YAML configs to focus/avoid specific paths/subdomains

### Considerations

- **Requires source code access** (white-box only)
- **API costs** - Uses Claude Sonnet 4.5 with maxTurns=10,000 per agent; 13 agents total
- **Docker required** - Full pipeline runs in Docker containers
- **Network access** - Agents need to reach the target application from the container

### Sample Results

Shannon ships with sample reports demonstrating exploitation of:
- OWASP Juice Shop (20+ critical vulns found)
- c{api}tal API
- crAPI

## Build Status

- TypeScript compilation: PASS (both main project and mcp-server)
- Shannon CLI: WORKING (`./shannon help` verified)
- Docker image: Cannot build in this environment (Chainguard registry unreachable)
- Docker build would work on a standard machine with internet access

## Files in This Workspace

```
shannon/                 # Cloned from github.com/KeygraphHQ/shannon
  shannon                # CLI entrypoint
  docker-compose.yml     # Temporal + worker orchestration
  .env                   # Credentials config (from .env.example)
  src/                   # TypeScript source
  dist/                  # Compiled JavaScript (built successfully)
  prompts/               # AI prompt templates
  configs/               # YAML configs + JSON schema
  sample-reports/        # Example pentest reports
  mcp-server/            # Shannon helper MCP server
```
