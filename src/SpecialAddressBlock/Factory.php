<?php

/**
 * This file is part of the Outsanity IP Analysis package.
 *
 * (c) Doug Harple <dharple@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Outsanity\IpAnalysis\SpecialAddressBlock;

use Exception;
use Outsanity\IpAnalysis\SpecialAddressBlock;

/**
 * Instantiates all instances of SpecialAddressBlock needed for processing.
 */
class Factory
{

    /**
     * Cache for holding the instantiated SpecialAddressBlocks.
     *
     * @var SpecialAddressBlock[]
     */
    protected static $all = [];

    /**
     * Cache for holding the instantiated IPV4 SpecialAddressBlocks.
     *
     * @var SpecialAddressBlock[]
     */
    protected static $allIpv4 = [];

    /**
     * Cache for holding the instantiated IPV6 SpecialAddressBlocks.
     *
     * @var SpecialAddressBlock[]
     */
    protected static $allIpv6 = [];

    /**
     * All of the SpecialAddressBlock data, represented as arrays.
     *
     * @var array
     */
    protected static $allRaw = [
        [
            'addressBlock' => '0.0.0.0/8',
            'allocationDate' => '1981-09',
            'destination' => false,
            'forwardable' => false,
            'globallyReachable' => false,
            'name' => '"This host on this network"',
            'reservedByProtocol' => true,
            'rfc' => '[RFC1122], Section 3.2.1.3',
            'source' => true,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '10.0.0.0/8',
            'allocationDate' => '1996-02',
            'destination' => true,
            'forwardable' => true,
            'globallyReachable' => false,
            'name' => 'Private-Use',
            'reservedByProtocol' => false,
            'rfc' => '[RFC1918]',
            'source' => true,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '100.64.0.0/10',
            'allocationDate' => '2012-04',
            'destination' => true,
            'forwardable' => true,
            'globallyReachable' => false,
            'name' => 'Shared Address Space',
            'reservedByProtocol' => false,
            'rfc' => '[RFC6598]',
            'source' => true,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '127.0.0.0/8',
            'allocationDate' => '1981-09',
            'destination' => false,
            'forwardable' => false,
            'globallyReachable' => false,
            'name' => 'Loopback',
            'reservedByProtocol' => true,
            'rfc' => '[RFC1122], Section 3.2.1.3',
            'source' => false,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '169.254.0.0/16',
            'allocationDate' => '2005-05',
            'destination' => true,
            'forwardable' => false,
            'globallyReachable' => false,
            'name' => 'Link Local',
            'reservedByProtocol' => true,
            'rfc' => '[RFC3927]',
            'source' => true,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '172.16.0.0/12',
            'allocationDate' => '1996-02',
            'destination' => true,
            'forwardable' => true,
            'globallyReachable' => false,
            'name' => 'Private-Use',
            'reservedByProtocol' => false,
            'rfc' => '[RFC1918]',
            'source' => true,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '192.0.0.0/24',
            'allocationDate' => '2010-01',
            'destination' => false,
            'forwardable' => false,
            'globallyReachable' => false,
            'name' => 'IETF Protocol Assignments',
            'reservedByProtocol' => false,
            'rfc' => '[RFC6890], Section 2.1',
            'source' => false,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '192.0.0.0/29',
            'allocationDate' => '2011-06',
            'destination' => true,
            'forwardable' => true,
            'globallyReachable' => false,
            'name' => 'IPv4 Service Continuity Prefix',
            'reservedByProtocol' => false,
            'rfc' => '[RFC7335]',
            'source' => true,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '192.0.0.8/32',
            'allocationDate' => '2015-03',
            'destination' => false,
            'forwardable' => false,
            'globallyReachable' => false,
            'name' => 'IPv4 dummy address',
            'reservedByProtocol' => false,
            'rfc' => '[RFC7600]',
            'source' => true,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '192.0.0.9/32',
            'allocationDate' => '2015-10',
            'destination' => true,
            'forwardable' => true,
            'globallyReachable' => true,
            'name' => 'Port Control Protocol Anycast',
            'reservedByProtocol' => false,
            'rfc' => '[RFC7723]',
            'source' => true,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '192.0.0.10/32',
            'allocationDate' => '2017-02',
            'destination' => true,
            'forwardable' => true,
            'globallyReachable' => true,
            'name' => 'Traversal Using Relays around NAT Anycast',
            'reservedByProtocol' => false,
            'rfc' => '[RFC8155]',
            'source' => true,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '192.0.0.170/32',
            'allocationDate' => '2013-02',
            'destination' => false,
            'forwardable' => false,
            'globallyReachable' => false,
            'name' => 'NAT64/DNS64 Discovery',
            'reservedByProtocol' => true,
            'rfc' => '[RFC-cheshire-sudn-ipv4only-dot-arpa-17][RFC7050], Section 2.2',
            'source' => false,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '192.0.2.0/24',
            'allocationDate' => '2010-01',
            'destination' => false,
            'forwardable' => false,
            'globallyReachable' => false,
            'name' => 'Documentation (TEST-NET-1)',
            'reservedByProtocol' => false,
            'rfc' => '[RFC5737]',
            'source' => false,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '192.31.196.0/24',
            'allocationDate' => '2014-12',
            'destination' => true,
            'forwardable' => true,
            'globallyReachable' => true,
            'name' => 'AS112-v4',
            'reservedByProtocol' => false,
            'rfc' => '[RFC7535]',
            'source' => true,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '192.52.193.0/24',
            'allocationDate' => '2014-12',
            'destination' => true,
            'forwardable' => true,
            'globallyReachable' => true,
            'name' => 'AMT',
            'reservedByProtocol' => false,
            'rfc' => '[RFC7450]',
            'source' => true,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '192.88.99.0/24',
            'allocationDate' => '2001-06',
            'destination' => false,
            'forwardable' => false,
            'globallyReachable' => false,
            'name' => 'Deprecated (6to4 Relay Anycast)',
            'reservedByProtocol' => false,
            'rfc' => '[RFC7526]',
            'source' => false,
            'terminationDate' => '2015-03',
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '192.168.0.0/16',
            'allocationDate' => '1996-02',
            'destination' => true,
            'forwardable' => true,
            'globallyReachable' => false,
            'name' => 'Private-Use',
            'reservedByProtocol' => false,
            'rfc' => '[RFC1918]',
            'source' => true,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '192.175.48.0/24',
            'allocationDate' => '1996-01',
            'destination' => true,
            'forwardable' => true,
            'globallyReachable' => true,
            'name' => 'Direct Delegation AS112 Service',
            'reservedByProtocol' => false,
            'rfc' => '[RFC7534]',
            'source' => true,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '198.18.0.0/15',
            'allocationDate' => '1999-03',
            'destination' => true,
            'forwardable' => true,
            'globallyReachable' => false,
            'name' => 'Benchmarking',
            'reservedByProtocol' => false,
            'rfc' => '[RFC2544]',
            'source' => true,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '198.51.100.0/24',
            'allocationDate' => '2010-01',
            'destination' => false,
            'forwardable' => false,
            'globallyReachable' => false,
            'name' => 'Documentation (TEST-NET-2)',
            'reservedByProtocol' => false,
            'rfc' => '[RFC5737]',
            'source' => false,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '203.0.113.0/24',
            'allocationDate' => '2010-01',
            'destination' => false,
            'forwardable' => false,
            'globallyReachable' => false,
            'name' => 'Documentation (TEST-NET-3)',
            'reservedByProtocol' => false,
            'rfc' => '[RFC5737]',
            'source' => false,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '240.0.0.0/4',
            'allocationDate' => '1989-08',
            'destination' => false,
            'forwardable' => false,
            'globallyReachable' => false,
            'name' => 'Reserved',
            'reservedByProtocol' => true,
            'rfc' => '[RFC1112], Section 4',
            'source' => false,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '255.255.255.255/32',
            'allocationDate' => '1984-10',
            'destination' => true,
            'forwardable' => false,
            'globallyReachable' => false,
            'name' => 'Limited Broadcast',
            'reservedByProtocol' => true,
            'rfc' => '[RFC8190]
               [RFC919], Section 7',
            'source' => false,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '192.0.0.171/32',
            'allocationDate' => '2013-02',
            'destination' => false,
            'forwardable' => false,
            'globallyReachable' => false,
            'name' => 'NAT64/DNS64 Discovery',
            'reservedByProtocol' => true,
            'rfc' => '[RFC-cheshire-sudn-ipv4only-dot-arpa-17][RFC7050], Section 2.2',
            'source' => false,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '224.0.0.0/4',
            'allocationDate' => null,
            'destination' => false,
            'forwardable' => null,
            'globallyReachable' => false,
            'name' => 'Multicast',
            'reservedByProtocol' => null,
            'rfc' => 'RFC4604',
            'source' => true,
            'terminationDate' => null,
            'type' => 'Other',
        ],
        [
            'addressBlock' => '::1/128',
            'allocationDate' => '2006-02',
            'destination' => false,
            'forwardable' => false,
            'globallyReachable' => false,
            'name' => 'Loopback Address',
            'reservedByProtocol' => true,
            'rfc' => '[RFC4291]',
            'source' => false,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '::/128',
            'allocationDate' => '2006-02',
            'destination' => false,
            'forwardable' => false,
            'globallyReachable' => false,
            'name' => 'Unspecified Address',
            'reservedByProtocol' => true,
            'rfc' => '[RFC4291]',
            'source' => true,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '::ffff:0:0/96',
            'allocationDate' => '2006-02',
            'destination' => false,
            'forwardable' => false,
            'globallyReachable' => false,
            'name' => 'IPv4-mapped Address',
            'reservedByProtocol' => true,
            'rfc' => '[RFC4291]',
            'source' => false,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '64:ff9b::/96',
            'allocationDate' => '2010-10',
            'destination' => true,
            'forwardable' => true,
            'globallyReachable' => true,
            'name' => 'IPv4-IPv6 Translat.',
            'reservedByProtocol' => false,
            'rfc' => '[RFC6052]',
            'source' => true,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '64:ff9b:1::/48',
            'allocationDate' => '2017-06',
            'destination' => true,
            'forwardable' => true,
            'globallyReachable' => false,
            'name' => 'IPv4-IPv6 Translat.',
            'reservedByProtocol' => false,
            'rfc' => '[RFC8215]',
            'source' => true,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '100::/64',
            'allocationDate' => '2012-06',
            'destination' => true,
            'forwardable' => true,
            'globallyReachable' => false,
            'name' => 'Discard-Only Address Block',
            'reservedByProtocol' => false,
            'rfc' => '[RFC6666]',
            'source' => true,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '2001::/23',
            'allocationDate' => '2000-09',
            'destination' => false,
            'forwardable' => false,
            'globallyReachable' => false,
            'name' => 'IETF Protocol Assignments',
            'reservedByProtocol' => false,
            'rfc' => '[RFC2928]',
            'source' => false,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '2001::/32',
            'allocationDate' => '2006-01',
            'destination' => true,
            'forwardable' => true,
            'globallyReachable' => null,
            'name' => 'TEREDO',
            'reservedByProtocol' => false,
            'rfc' => '[RFC4380]
               [RFC8190]',
            'source' => true,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '2001:1::1/128',
            'allocationDate' => '2015-10',
            'destination' => true,
            'forwardable' => true,
            'globallyReachable' => true,
            'name' => 'Port Control Protocol Anycast',
            'reservedByProtocol' => false,
            'rfc' => '[RFC7723]',
            'source' => true,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '2001:1::2/128',
            'allocationDate' => '2017-02',
            'destination' => true,
            'forwardable' => true,
            'globallyReachable' => true,
            'name' => 'Traversal Using Relays around NAT Anycast',
            'reservedByProtocol' => false,
            'rfc' => '[RFC8155]',
            'source' => true,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '2001:2::/48',
            'allocationDate' => '2008-04',
            'destination' => true,
            'forwardable' => true,
            'globallyReachable' => false,
            'name' => 'Benchmarking',
            'reservedByProtocol' => false,
            'rfc' => '[RFC5180][RFC Errata 
                 1752]',
            'source' => true,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '2001:3::/32',
            'allocationDate' => '2014-12',
            'destination' => true,
            'forwardable' => true,
            'globallyReachable' => true,
            'name' => 'AMT',
            'reservedByProtocol' => false,
            'rfc' => '[RFC7450]',
            'source' => true,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '2001:4:112::/48',
            'allocationDate' => '2014-12',
            'destination' => true,
            'forwardable' => true,
            'globallyReachable' => true,
            'name' => 'AS112-v6',
            'reservedByProtocol' => false,
            'rfc' => '[RFC7535]',
            'source' => true,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '2001:10::/28',
            'allocationDate' => '2007-03',
            'destination' => false,
            'forwardable' => false,
            'globallyReachable' => false,
            'name' => 'Deprecated (previously ORCHID)',
            'reservedByProtocol' => false,
            'rfc' => '[RFC4843]',
            'source' => false,
            'terminationDate' => '2014-03',
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '2001:20::/28',
            'allocationDate' => '2014-07',
            'destination' => true,
            'forwardable' => true,
            'globallyReachable' => true,
            'name' => 'ORCHIDv2',
            'reservedByProtocol' => false,
            'rfc' => '[RFC7343]',
            'source' => true,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '2001:db8::/32',
            'allocationDate' => '2004-07',
            'destination' => false,
            'forwardable' => false,
            'globallyReachable' => false,
            'name' => 'Documentation',
            'reservedByProtocol' => false,
            'rfc' => '[RFC3849]',
            'source' => false,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '2002::/16',
            'allocationDate' => '2001-02',
            'destination' => true,
            'forwardable' => true,
            'globallyReachable' => null,
            'name' => '6to4',
            'reservedByProtocol' => false,
            'rfc' => '[RFC3056]',
            'source' => true,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => '2620:4f:8000::/48',
            'allocationDate' => '2011-05',
            'destination' => true,
            'forwardable' => true,
            'globallyReachable' => true,
            'name' => 'Direct Delegation AS112 Service',
            'reservedByProtocol' => false,
            'rfc' => '[RFC7534]',
            'source' => true,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => 'fc00::/7',
            'allocationDate' => '2005-10',
            'destination' => true,
            'forwardable' => true,
            'globallyReachable' => false,
            'name' => 'Unique-Local',
            'reservedByProtocol' => false,
            'rfc' => '[RFC4193]
               [RFC8190]',
            'source' => true,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => 'fe80::/10',
            'allocationDate' => '2006-02',
            'destination' => true,
            'forwardable' => false,
            'globallyReachable' => false,
            'name' => 'Link-Local Unicast',
            'reservedByProtocol' => true,
            'rfc' => '[RFC4291]',
            'source' => true,
            'terminationDate' => null,
            'type' => 'IANA',
        ],
        [
            'addressBlock' => 'ff00::/8',
            'allocationDate' => null,
            'destination' => false,
            'forwardable' => null,
            'globallyReachable' => false,
            'name' => 'Multicast',
            'reservedByProtocol' => null,
            'rfc' => 'RFC4604',
            'source' => true,
            'terminationDate' => null,
            'type' => 'Other',
        ],
    ];

    /**
     * Loads all of the SpecialAddressBlocks.
     *
     * @return SpecialAddressBlock[]
     *
     * @throws Exception If a block cannot be unserialized.
     */
    public static function getAll()
    {
        if (empty(static::$all)) {
            foreach (static::$allRaw as $row) {
                static::$all[] = SpecialAddressBlock::__set_state($row);
            }
        }

        return static::$all;
    }

    /**
     * Loads all of the IPV4 SpecialAddressBlocks.
     *
     * @return SpecialAddressBlock[]
     *
     * @throws Exception If a block cannot be unserialized.
     */
    public static function getIpv4()
    {
        if (empty(static::$allIpv4)) {
            foreach (static::getAll() as $block) {
                if ($block->isIpv4()) {
                    static::$allIpv4[] = $block;
                }
            }
        }

        return static::$allIpv4;
    }

    /**
     * Loads all of the IPV6 SpecialAddressBlocks.
     *
     * @return SpecialAddressBlock[]
     *
     * @throws Exception If a block cannot be unserialized.
     */
    public static function getIpv6()
    {
        if (empty(static::$allIpv6)) {
            foreach (static::getAll() as $block) {
                if ($block->isIpv6()) {
                    static::$allIpv6[] = $block;
                }
            }
        }

        return static::$allIpv6;
    }
}
