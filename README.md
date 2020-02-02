# PHP IP Analyzer

[![Build Status](https://travis-ci.org/dharple/ip-analysis.svg?branch=master)](https://travis-ci.org/dharple/ip-analysis)

Analyzes IP addresses to help programmatically identify IPs that are globally
reachable, or not, and find out additional details about the IP.

# Installation

If you're using composer, run:
```shell
composer require outsanity/ip-analysis
```

# Usage

```php
<?php

require 'vendor/autoload.php';

use Outsanity\IpAnalysis\IpAnalysis;

$ip = new IpAnalysis('127.0.0.1');
echo 'documentation: ' . ($ip->isDocumentation()  ? 'yes' : 'no') . "\n"; // 192.0.2.65, 2001:db8:1:3::2
echo 'global: ' .        ($ip->isGlobal()         ? 'yes' : 'no') . "\n"; // 8.8.8.8, 2001:4860:4860::8888
echo 'loopback: ' .      ($ip->isLoopback()       ? 'yes' : 'no') . "\n"; // 127.0.0.1, ::1
echo 'multicast: ' .     ($ip->isMulticast()      ? 'yes' : 'no') . "\n"; // 224.0.1.1, ff00::101
echo 'private: ' .       ($ip->isPrivateNetwork() ? 'yes' : 'no') . "\n"; // 10.0.0.1, 192.168.0.1, fd11:1111:1111::1
echo 'subnet: ' .        ($ip->isLocalNetwork()   ? 'yes' : 'no') . "\n"; // 169.254.0.1, fe80::6450:6a14:93ba:de09
```

Expected output:
```
documentation: no
global: no
loopback: yes
multicast: no
private: no
subnet: no
```

# Thanks

The rules come from the [IANA IPv4 Special Address Registry] and the
[IANA IPv6 Special Address Registry].

Additional help came from the [Wikipedia Reserved IP Addresses] page and the
[RIPE IPv6 Reference Card].

[IANA IPv4 Special Address Registry]: https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
[IANA IPv6 Special Address Registry]: https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
[RIPE IPv6 Reference Card]: https://www.ripe.net/participate/member-support/lir-basics/ipv6_reference_card.pdf
[Wikipedia Reserved IP Addresses]: https://en.wikipedia.org/wiki/Reserved_IP_addresses

