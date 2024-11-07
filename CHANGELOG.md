# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- The minimum symfony/http-foundation version is now 5.4.46, due to
  [CVE-2024-50345].
- Updates from IANA website
  - The Segment Routing (SRv6) SIDs block is now [RFC9602].

## [3.2.0] - 2024-10-13

### Changed

- Updates from IANA website
  - Added 3fff::/20 for an expansion to the IPv6 Documentation Space.
    [RFC9637].
  - Minor name change on the 2001:1::3/128 address block.

## [3.1.0] - 2024-05-01

### Changed

- Updates from IANA website
  - Added 2001:1::3/128, for DNS-SD Service Registration Protocol Anycast
    Address.  [RFC-ietf-dnssd-srp-25]
  - Added 5f00::/16, for Segment Routing (SRv6) SIDs.  [RFC-ietf-6man-sids-06]

## [3.0.0] - 2023-10-19

### Changed

- The minimum Symfony version is now 5.4.

## [2.0.0] - 2023-10-18

### Changed

- The minimum PHP version is now 8.1.  Applied Rector-suggested changes.
- The minimum Symfony version is now 4.4.

## [1.0.0] - 2023-03-31

### Changed

- Updates from IANA website
  - 0.0.0.0 the host is now split from 0.0.0.0/8 the network.
  - Added 2001:30::/28, for Drone Remote ID Protocol Entity Tags (DETs) Prefix.
    [RFC9374]

## [0.4.0] - 2021-01-11

### Added

- Added IpAnalysis::getIp()

### Changed

- Added a few missing PHP type hints.
- Added PHP 8.0 to the Travis test cases.
- Added Symfony 5.1 and 5.2 to the Travis test cases.
- Added symfony/serializer to the list of suggested libraries, because it
  drives the annotations in SpecialAddressBlock.
- IANA IPv4 data based on 2020-04-06 and 2020-09-04 changes.  [RFC8880] is now
  associated with two IPv4 blocks.
- Switched composer PHP version to simpler format.

## [0.3.0] - 2020-02-15

### Changed

- A Factory class is now being used to instantiate all of the IP rules, instead
  of include files.

## [0.2.1] - 2020-02-14

### Changed

- All of the IANA conversion logic has been moved to the [IP Analysis Helper] project.

## [0.2.0] - 2020-02-04

### Added

- Caching on loaded ipv4/ipv6 class rules.
- Docblocks
- Unit tests on SpecialAddressBlock.

### Changed

- Consolidated IanaRule and OtherRule into SpecialAddressBlock.
- Exposed IpAnalysis::analyze() as ::getSpecialAddressBlock().

### Fixed

- IP addresses specified in documentation match examples, and are present in
  unit tests.
- Types on SpecialAddressBlock are all nullable now.  N/A in the source file is
  stored as null.

## [0.1.0] - 2020-01-31

### Added

- Basic IP Analysis tools
- CSV parser for IANA IPv[46] Special-Purpose Address Registry

[Unreleased]: https://github.com/dharple/ip-analysis/compare/v3.2.0...main
[3.2.0]: https://github.com/dharple/ip-analysis/compare/v3.1.0...v3.2.0
[3.1.0]: https://github.com/dharple/ip-analysis/compare/v3.0.0...v3.1.0
[3.0.0]: https://github.com/dharple/ip-analysis/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/dharple/ip-analysis/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/dharple/ip-analysis/compare/v0.4.0...v1.0.0
[0.4.0]: https://github.com/dharple/ip-analysis/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/dharple/ip-analysis/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/dharple/ip-analysis/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/dharple/ip-analysis/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/dharple/ip-analysis/releases/tag/v0.1.0

[CVE-2024-50345]: https://nvd.nist.gov/vuln/detail/CVE-2024-50345
[IP Analysis Helper]: https://github.com/dharple/ip-analysis-helper
[RFC8880]: https://www.iana.org/go/rfc8880
[RFC9374]: https://www.iana.org/go/rfc9374
[RFC9602]: https://www.iana.org/go/rfc9602
[RFC9637]: https://www.iana.org/go/rfc9637
[RFC-ietf-6man-sids-06]: https://www.iana.org/go/draft-ietf-6man-sids-06
[RFC-ietf-dnssd-srp-25]: https://www.iana.org/go/draft-ietf-dnssd-srp-25
