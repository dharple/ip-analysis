<?php

/**
 * This file is part of the Outsanity IP Analysis package.
 *
 * (c) Doug Harple <dharple@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Outsanity\IpAnalysis;

use Symfony\Component\HttpFoundation\IpUtils;

/**
 * Analyzes IPs an returns information about them.
 */
class IpAnalysis
{
    /**
     * The matched SpecialAddressBlock, if any.
     *
     * @var ?SpecialAddressBlock
     */
    protected $block;

    /**
     * The passed IP address.
     *
     * @var string
     */
    protected $ip;

    /**
     * The IPv4 blocks.
     *
     * @var SpecialAddressBlock[]
     */
    protected static $ipv4 = null;

    /**
     * The IPv6 blocks.
     *
     * @var SpecialAddressBlock[]
     */
    protected static $ipv6 = null;

    /**
     * Whether or not processing has been performed on the IP address.
     *
     * @var bool
     */
    protected $processed = false;

    /**
     * IANA names associated with loopback addresses.
     *
     * @var string[]
     */
    public const NAME_LOOPBACK = [
        'Loopback',
        'Loopback Address',
    ];

    /**
     * IANA names associated with private addresses.
     *
     * @var string[]
     */
    public const NAME_PRIVATE = [
        'Private-Use',
        'Unique-Local',
    ];

    /**
     * IANA names associated with local addresses.
     *
     * @var string[]
     */
    public const NAME_LOCAL = [
        'Limited Broadcast',
        'Link Local',
        'Link-Local Unicast',
    ];

    /**
     * Names associated with multicast addresses.
     *
     * @var string[]
     */
    public const NAME_MULTICAST = [
        'Multicast',
    ];

    /**
     * Constructs a new analyzer.
     *
     * @param string $ip The IP to analyze.
     */
    public function __construct(string $ip)
    {
        $this->ip = $ip;
    }

    /**
     * Analyzes the passed IP address and returns the matching special address block, if any.
     *
     * @return ?SpecialAddressBlock
     */
    public function getSpecialAddressBlock(): ?SpecialAddressBlock
    {
        if (!$this->processed) {
            // follow Symfony rule
            $is6 = substr_count($this->ip, ':') > 1;
            if ($is6) {
                $blocks = static::$ipv6 ?? static::$ipv6 = include dirname(__DIR__) . '/data/iana-ipv6-special-registry-1.php';
            } else {
                $blocks = static::$ipv4 ?? static::$ipv4 = include dirname(__DIR__) . '/data/iana-ipv4-special-registry-1.php';
            }

            foreach ($blocks as $block) {
                if (IpUtils::checkIp($this->ip, $block->getAddressBlock())) {
                    $this->block = $block;
                    break;
                }
            }

            $this->processed = true;
        }

        return $this->block;
    }

    /**
     * Whether or not the IP is from a block meant for documentation.
     *
     * Examples: 192.0.2.65, 2001:db8:1:3::2
     *
     * @return bool
     */
    public function isDocumentation(): bool
    {
        $block = $this->getSpecialAddressBlock();
        return ($block !== null && preg_match('/^Documentation/', $block->getName()));
    }

    /**
     * Whether or not the IP address is globally reachable.
     *
     * Examples: 8.8.8.8, 2001:4860:4860::8888
     *
     * @return bool
     */
    public function isGlobal(): bool
    {
        $block = $this->getSpecialAddressBlock();
        return $block ? $block->getGloballyReachable() : true;
    }

    /**
     * Whether or not the IP address is a local (subnet-only) address.
     *
     * Examples: 169.254.13.1, fe80::6450:6a14:93ba:de09
     *
     * @return bool
     */
    public function isLocalNetwork(): bool
    {
        $block = $this->getSpecialAddressBlock();
        return ($block !== null && in_array($block->getName(), static::NAME_LOCAL));
    }

    /**
     * Whether or not the IP address is a loopback address.
     *
     * Examples: 127.0.0.1, ::1
     *
     * @return bool
     */
    public function isLoopback(): bool
    {
        $block = $this->getSpecialAddressBlock();
        return ($block !== null && in_array($block->getName(), static::NAME_LOOPBACK));
    }

    /**
     * Whether or not the IP address is a multicast address.
     *
     * Examples: 224.0.1.1, ff00::101
     *
     * @return bool
     */
    public function isMulticast(): bool
    {
        $block = $this->getSpecialAddressBlock();
        return ($block !== null && in_array($block->getName(), static::NAME_MULTICAST));
    }

    /**
     * Whether or not the IP address is on a private network.
     *
     * Examples: 10.0.0.1, 192.168.0.1, fd11:1111:1111::1
     *
     * @return bool
     */
    public function isPrivateNetwork(): bool
    {
        $block = $this->getSpecialAddressBlock();
        return ($block !== null && in_array($block->getName(), static::NAME_PRIVATE));
    }

    /**
     * Whether or not the IP address falls under one or more known special blocks.
     *
     * @return bool
     */
    public function isSpecial(): bool
    {
        return ($this->getSpecialAddressBlock() !== null);
    }
}
