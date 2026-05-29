# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run tests
composer test
# or directly:
vendor/bin/phpunit

# Run a single test file
vendor/bin/phpunit tests/Unit/IpAnalysisTest.php

# Run a single test method
vendor/bin/phpunit --filter testIsLoopback

# Static analysis (level 5)
composer phpstan

# Code style check
composer phpcs

# Code style fix
composer phpcbf
```

## Architecture

This is a PHP library (`outsanity/ip-analysis`) for classifying IP addresses against IANA Special-Purpose Address registries.

**Entry point:** `IpAnalysis` (`src/IpAnalysis.php`) — instantiate with an IP string, then call boolean classification methods (`isLoopback()`, `isPrivateNetwork()`, `isGlobal()`, `isDocumentation()`, `isLocalNetwork()`, `isMulticast()`, `isSpecial()`) or `getSpecialAddressBlock()` to get the matched block.

**Data:** `SpecialAddressBlock\Factory` (`src/SpecialAddressBlock/Factory.php`) holds all CIDR block definitions inline as a static `$allRaw` array. It lazy-loads and caches three views: all blocks, IPv4-only, IPv6-only. No external data files or network calls.

**Block matching:** `IpAnalysis::getSpecialAddressBlock()` distinguishes IPv4 vs IPv6 by counting `:` characters (`> 1` ⇒ IPv6, following Symfony convention). This is a heuristic, not validation — the input is never checked to be a well-formed IP, and `IpUtils::checkIp()` returns false for malformed input. It then iterates the appropriate factory list and delegates CIDR matching to `Symfony\Component\HttpFoundation\IpUtils::checkIp()`. Matching stops at the first hit — block order in `$allRaw` matters for overlapping CIDRs. When adding overlapping blocks, place broader prefixes carefully and verify the resulting classification — today all overlapping pairs share the same `globallyReachable` outcome, so reordering has no security impact, but that invariant is not enforced anywhere.

**Classification logic:** The `is*()` methods in `IpAnalysis` match by block name against constants (`NAME_LOOPBACK`, `NAME_PRIVATE`, etc.), not by CIDR range directly. When adding a new block type, add both the name constant and the corresponding `is*()` method. `isGlobal()` returns `true` for unrecognized IPs (no matching block) since the absence of a special block implies global reachability.

**`SpecialAddressBlock`:** A value object with full IANA registry fields (RFC, allocation date, forwardable, destination, source, globally reachable, reserved-by-protocol). The `checkBool()` / `checkString()` helpers normalize IANA table values including `"N/A"` and footnote annotations like `[1]`. `__set_state()` enables PHP `var_export()` round-tripping.

**Namespace:** `Outsanity\IpAnalysis` (src), `Outsanity\Tests` (tests). PHP ≥ 8.1.2 required.

## Security considerations

This library is commonly used to make trust/reachability decisions (e.g. SSRF allow/deny lists). Several behaviors are intentional but easy to weaken accidentally — preserve them, and call them out in PR descriptions if you change them:

- **No input validation.** The constructor stores the raw string; `IpUtils` silently returns `false` for anything `filter_var()` rejects (octal-looking IPs, `1.2.3.4/0`, hostnames, whitespace). Such input matches no block.
- **`isGlobal()` fails open.** Unmatched IPs return `true`. Do NOT rely on this as a fail-safe security gate without validating input first. If you change the default, treat it as a behavior/breaking change.
- **Embedded-IPv4 IPv6 forms are NOT decomposed.** `::ffff:127.0.0.1` (loopback), `::ffff:10.0.0.1` (private), and NAT64 `64:ff9b::/96` are classified by their container block only, so category checks (`isLoopback`/`isPrivateNetwork`/`isLocalNetwork`) can be bypassed. If you add unwrapping logic, re-run classification on the embedded IPv4.
- **`globallyReachable` is tri-state (`?bool`).** `null` (TEREDO, 6to4, multicast) is coerced to `false` by `isGlobal()`'s `: bool` return type. Keep this in mind before widening or narrowing the return type.
