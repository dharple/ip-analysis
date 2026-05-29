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

**Block matching:** `IpAnalysis::getSpecialAddressBlock()` distinguishes IPv4 vs IPv6 by counting `:` characters (following Symfony convention), then iterates the appropriate factory list and delegates CIDR matching to `Symfony\Component\HttpFoundation\IpUtils::checkIp()`. Matching stops at the first hit — block order in `$allRaw` matters for overlapping CIDRs.

**Classification logic:** The `is*()` methods in `IpAnalysis` match by block name against constants (`NAME_LOOPBACK`, `NAME_PRIVATE`, etc.), not by CIDR range directly. When adding a new block type, add both the name constant and the corresponding `is*()` method. `isGlobal()` returns `true` for unrecognized IPs (no matching block) since the absence of a special block implies global reachability.

**`SpecialAddressBlock`:** A value object with full IANA registry fields (RFC, allocation date, forwardable, destination, source, globally reachable, reserved-by-protocol). The `checkBool()` / `checkString()` helpers normalize IANA table values including `"N/A"` and footnote annotations like `[1]`. `__set_state()` enables PHP `var_export()` round-tripping.

**Namespace:** `Outsanity\IpAnalysis` (src), `Outsanity\Tests` (tests). PHP ≥ 8.1.2 required.
