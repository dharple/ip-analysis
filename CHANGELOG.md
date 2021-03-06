# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[Unreleased]: https://github.com/dharple/ip-analysis/compare/v0.4.0...master
[0.4.0]: https://github.com/dharple/ip-analysis/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/dharple/ip-analysis/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/dharple/ip-analysis/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/dharple/ip-analysis/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/dharple/ip-analysis/releases/tag/v0.1.0

[IP Analysis Helper]: https://github.com/dharple/ip-analysis-helper
[RFC8880]: https://datatracker.ietf.org/doc/rfc8880/
