<?php

namespace Outsanity\IpAnalysis;

use Symfony\Component\HttpFoundation\IpUtils;

class IpAnalysis
{
    public const SCOPE_DOC     = 'Documentation';
    public const SCOPE_GLOBAL  = 'Internet';
    public const SCOPE_HOST    = 'Host';
    public const SCOPE_PRIVATE = 'Private network';
    public const SCOPE_SUBNET  = 'Subnet';
    public const SCOPE_CURRENT = 'Software';

    public const DEFAULT_DESC  = 'Global IP Address';
    public const DEFAULT_SRC   = 'https://en.wikipedia.org/wiki/Reserved_IP_addresses';

    protected $description;
    protected $ip;
    protected $reserved;

    /**
     * From https://en.wikipedia.org/wiki/Reserved_IP_addresses
     *
     * @var array
     */
    protected $reservedRanges = [
        '0.0.0.0/8' => [
            'Description' => 'Current network (only valid as source address).',
            'Scope'       => self::SCOPE_CURRENT,
        ],
        '10.0.0.0/8' => [
            'Description' => 'Used for local communications within a private network.',
            'Scope'       => self::SCOPE_PRIVATE,
        ],
        '100.64.0.0/10' => [
            'Description' => 'Shared address space for communications between a service provider and its subscribers when using a carrier-grade NAT.',
            'Scope'       => self::SCOPE_PRIVATE,
        ],
        '127.0.0.0/8' => [
            'Description' => 'Used for loopback addresses to the local host.',
            'Scope'       => self::SCOPE_HOST,
        ],
        '169.254.0.0/16' => [
            'Description' => 'Used for link-local addresses between two hosts on a single link when no IP address is otherwise specified, such as would have normally been retrieved from a DHCP server.',
            'Scope'       => self::SCOPE_SUBNET,
        ],
        '172.16.0.0/12' => [
            'Description' => 'Used for local communications within a private network.',
            'Scope'       => self::SCOPE_PRIVATE,
        ],
        '192.0.0.0/24' => [
            'Description' => 'IETF Protocol Assignments.',
            'Scope'       => self::SCOPE_PRIVATE,
        ],
        '192.0.2.0/24' => [
            'Description' => 'Assigned as TEST-NET-1, documentation and examples.',
            'Scope'       => self::SCOPE_DOC,
        ],
        '192.88.99.0/24' => [
            'Description' => 'Reserved. Formerly used for IPv6 to IPv4 relay (included IPv6 address block 2002::/16).',
            'Scope'       => self::SCOPE_GLOBAL,
        ],
        '192.168.0.0/16' => [
            'Description' => 'Used for local communications within a private network.',
            'Scope'       => self::SCOPE_PRIVATE,
        ],
        '198.18.0.0/15' => [
            'Description' => 'Used for benchmark testing of inter-network communications between two separate subnets.',
            'Scope'       => self::SCOPE_PRIVATE,
        ],
        '198.51.100.0/24' => [
            'Description' => 'Assigned as TEST-NET-2, documentation and examples.',
            'Scope'       => self::SCOPE_DOC,
        ],
        '203.0.113.0/24' => [
            'Description' => 'Assigned as TEST-NET-3, documentation and examples.',
            'Scope'       => self::SCOPE_DOC,
        ],
        '224.0.0.0/4' => [
            'Description' => 'In use for IP multicast. (Former Class D network).',
            'Scope'       => self::SCOPE_GLOBAL,
        ],
        '240.0.0.0/4' => [
            'Description' => 'Reserved for future use. (Former Class E network).',
            'Scope'       => self::SCOPE_GLOBAL,
        ],
        '255.255.255.255/32' => [
            'Description' => 'Reserved for the "limited broadcast" destination address.',
            'Scope'       => self::SCOPE_SUBNET,
        ],
    ];

    protected $scope;

    protected $source;

    public function __construct($ip)
    {
        $this->ip = $ip;
    }

    protected function analyze()
    {
        if ($this->reserved !== null) {
            return;
        }

        $this->reserved = false;
        $this->description = static::DEFAULT_DESC;
        $this->scope       = static::SCOPE_GLOBAL;
        $this->source      = static::DEFAULT_SRC;

        foreach ($this->reservedRanges as $range => $details) {
            if (IpUtils::checkIp($this->ip, $range)) {
                $this->reserved = true;
                $this->scope = $details['Scope'];
                $this->description = $details['Description'];
                break;
            }
        }
    }

    public function getDescription()
    {
        $this->analyze();
        return $this->description;
    }

    public function getScope()
    {
        $this->analyze();
        return $this->scope;
    }

    public function getSource()
    {
        $this->analyze();
        return $this->source;
    }

    public function isReserved()
    {
        $this->analyze();
        return $this->reserved;
    }
}
