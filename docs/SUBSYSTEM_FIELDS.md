# Subsystem Field Specification

This document defines the normalized event schema for the supported security subsystems.

## Supported Subsystems

- `ddos`
- `firewall`
- `ips`
- `appcontrol`
- `waf`
- `websec`
- `mail`
- `vpn`

## Common Fields (All Subsystems)

Every event can contain these common fields:

- `timestamp`
- `subsystem`
- `protocol`
- `srcip` (IPv4/IPv6 string)
- `dstip` (IPv4/IPv6 string)
- `srcport` (can be empty)
- `dstport` (can be empty)
- `rule` (string; examples: `bannedextension`, `bannedMIME`, `site_unreachable`, `virus`, `spam`, `shellcode_error`, `neterror`)
- `action` (`pass` or `block`)

## Subsystem-Specific Fields

### 1) DDoS

Two variants are supported.

Variant A:
- `attacktype` (`DDoS` or `DoS`)
- `ip`
- `direction` (`in` or `out`)
- `status` (`end`)
- `count`

Variant B:
- `attacktype` (`DDoS` or `DoS`)
- `ip`
- `pps` (integer)
- `mbps` (integer)
- `status` (`end`)
- `count`

### 2) Firewall

- `count`
- `len`
- `ttl`
- `tos`
- `initf` (input interface, e.g. `eth0`)
- `outitf` (output interface, e.g. `eth1`)

### 3) IPS

- `groupid`
- `reason`
- `alertcount`
- `dropcount`

### 4) AppControl

- `count`
- `len`
- `ttl`
- `tos`
- `initf`
- `outitf`
- `mark` (hex string, e.g. `0x2001`)

### 5) WAF (Web Application Firewall)

- `reason`
- `client` (IPv4/IPv6)
- `server` (IPv4/IPv6)
- `vhost` (`ip:port`)
- `count`

### 6) WebSec

- `content` (formatted text payload)

Examples:
- `http 34.2.34.1 http://3.4.2.3/test/1.jpg /Denied/Banned File Extension .jpg`
- `http 3.1.2.4 http://3.1.2.4/test/1.pdf /Denied/Banned File MIME type text/pdf`
- `http 3.1.2.4 http://3.1.2.4/work /NetError/The site requested is not responding`

### 7) Mail

- `id` (integer)
- `serverity` (string; example: `info`, `warn`)  
  Note: source logs may use `serverity` spelling.
- `sys` (example: `securemail`)
- `sub` (example: `smtp`)
- `type` (integer)
- `from`
- `to` (email address)
- `subject`
- `srcuser`
- `srcdomain`
- `dstuser`
- `dstdomain`
- `size`
- `extra`

### 8) VPN

Two variants are supported:

For `rule=virtualfirewall`:
- `hub`
- `srcuser`
- `connection` (example: `CID-222`)
- `dstuser`
- `count`

For `rule=accesslist`:
- `hub`
- `srcuser`
- `connection` (example: `CID-222`)
- `count`

## Parser Notes

- Parser normalization is implemented in `backend/event_parser.py`.
- Unknown keys are retained in `raw_data`.
- Subsystem-specific keys are also retained under `subsystem_fields`.
