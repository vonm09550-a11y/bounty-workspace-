# Threshold Network Bug Bounty Reconnaissance Report

**Target:** https://www.threshold.network
**Date:** 2026-01-19
**Program:** Threshold Network Bug Bounty

---

## Executive Summary

Performed reconnaissance on threshold.network. Found 30 subdomains with 8 returning no response (potential subdomain takeover candidates). Primary infrastructure uses Cloudflare WAF with Amazon S3/CloudFront backend.

---

## Subdomains Discovered (30)

### Live (HTTP 200)
| Subdomain | Notes |
|-----------|-------|
| www.threshold.network | Main website |
| api.threshold.network | API endpoint |
| delegates.threshold.network | Delegates portal |
| forum.threshold.network | Community forum |
| newsletter.threshold.network | Newsletter signup |

### Redirecting (HTTP 301)
| Subdomain | Redirects To |
|-----------|-------------|
| blog.threshold.network | External blog |
| dao.threshold.network | DAO interface |
| dashboard.threshold.network | App dashboard |
| preview.threshold.network | Preview environment |
| storybook.threshold.network | Component library |
| tbtc-dkg.threshold.network | tBTC DKG service |
| bob.test.threshold.network | Test environment |

### Service Unavailable (HTTP 503)
| Subdomain | Status |
|-----------|--------|
| arbitrum.threshold.network | 503 |
| discord.threshold.network | 503 |
| docs.threshold.network | 503 |
| gov.threshold.network | 503 |
| governance.threshold.network | 503 |
| monitoring.threshold.network | 503 |
| dashboard.test.threshold.network | 503 |
| thusd.threshold.network | 503 |

### POTENTIAL SUBDOMAIN TAKEOVER (HTTP 000 - No Response)
| Subdomain | Risk |
|-----------|------|
| api-docs.threshold.network | HIGH |
| dapp.threshold.network | HIGH |
| public.monitoring.threshold.network | HIGH |
| preview.dashboard.test.threshold.network | MEDIUM |
| dashboard-goerli.test.threshold.network | MEDIUM |
| monitoring.test.threshold.network | MEDIUM |
| public.monitoring.test.threshold.network | MEDIUM |
| status.test.threshold.network | MEDIUM |

---

## Technology Stack

| Component | Technology |
|-----------|------------|
| WAF | Cloudflare |
| CDN | CloudFront |
| Storage | Amazon S3 |
| TLS | TLS 1.3 |
| HSTS | Enabled (1 year) |
| CSP | frame-ancestors 'self' |

---

## Security Headers Analysis

**Present:**
- Strict-Transport-Security: max-age=31536000
- Content-Security-Policy: frame-ancestors 'self'
- X-Frame-Options: SAMEORIGIN
- X-Content-Type-Options: nosniff

**Recommendations:**
- HSTS could include `includeSubDomains`
- HSTS could add `preload` directive

---

## Potential Vulnerabilities to Investigate

### 1. Subdomain Takeover (Critical if exploitable)
**Subdomains returning no response may be claimable:**
- api-docs.threshold.network
- dapp.threshold.network
- public.monitoring.threshold.network

**Next Steps:**
- Check CNAME records for external service pointers
- Verify if underlying services (S3, GitHub Pages, Heroku, etc.) are unclaimed

### 2. 503 Service Unavailable Subdomains
Multiple production subdomains returning 503 may indicate:
- Misconfigured services
- Abandoned infrastructure
- Potential for exploitation if underlying services exposed

### 3. Test Environment Exposure
Multiple `.test.threshold.network` subdomains discovered:
- dashboard.test.threshold.network
- dashboard-goerli.test.threshold.network
- monitoring.test.threshold.network

Test environments may have weaker security controls.

---

## In-Scope Impacts (per bounty rules)

**Critical ($1,000-$3,000):**
- Subdomain takeover with wallet interaction
- Direct theft of user funds
- Sensitive data retrieval (DB passwords, blockchain keys)
- Account takeover without interaction

**High ($1,000):**
- HTML injection (persistent)
- Changing user details with 1 click

**Medium ($300):**
- Open redirect
- Reflected HTML injection
- Taking down application

---

## Next Steps

1. Deep dive on subdomain takeover candidates
2. Test dashboard app for wallet-related vulnerabilities
3. Analyze API endpoints for injection vulnerabilities
4. Check for sensitive data exposure in JS bundles
5. Test authentication/session handling

---

*Report generated during authorized bug bounty testing*
