<?php

namespace Outsanity\IpAnalysis;

use Symfony\Component\HttpFoundation\IpUtils;

class IpAnalysis
{
    protected $ianaRule;
    protected $ip;
    protected $processed = false;

    public const NAME_LOOPBACK = [
        'Loopback',
        'Loopback Address',
    ];

    public const NAME_PRIVATE = [
        'Private-Use',
        'Unique-Local',
    ];

    public const NAME_LOCAL = [
        'Limited Broadcast',
        'Link Local',
        'Link-Local Unicast',
    ];

    public const NAME_MULTICAST = [
        'Multicast',
    ];

    public function __construct($ip)
    {
        $this->ip = $ip;
    }

    protected function analyze(): ?IanaRule
    {
        if (!$this->processed) {
            // follow Symfony rule
            $is6 = substr_count($this->ip, ':') > 1;
            if ($is6) {
                $ianaRules = include dirname(__DIR__) . '/data/iana-ipv6-special-registry-1.php';
            } else {
                $ianaRules = include dirname(__DIR__) . '/data/iana-ipv4-special-registry-1.php';
            }

            foreach ($ianaRules as $ianaRule) {
                if (IpUtils::checkIp($this->ip, $ianaRule->getAddressBlock())) {
                    $this->ianaRule = $ianaRule;
                    break;
                }
            }
        }

        $this->processed = true;
        return $this->ianaRule;
    }

    public function isDocumentation(): bool
    {
        $ianaRule = $this->analyze();
        return ($ianaRule !== null && preg_match('/^Documentation/', $ianaRule->getName()));
    }

    public function isGlobal(): bool
    {
        $ianaRule = $this->analyze();
        return $ianaRule ? $ianaRule->getGloballyReachable() : true;
    }

    public function isLocalNetwork(): bool
    {
        $ianaRule = $this->analyze();
        return ($ianaRule !== null && in_array($ianaRule->getName(), static::NAME_LOCAL));
    }

    public function isLoopback(): bool
    {
        $ianaRule = $this->analyze();
        return ($ianaRule !== null && in_array($ianaRule->getName(), static::NAME_LOOPBACK));
    }

    public function isMulticast(): bool
    {
        $ianaRule = $this->analyze();
        return ($ianaRule !== null && in_array($ianaRule->getName(), static::NAME_MULTICAST));
    }

    public function isPrivateNetwork(): bool
    {
        $ianaRule = $this->analyze();
        return ($ianaRule !== null && in_array($ianaRule->getName(), static::NAME_PRIVATE));
    }

    public function isSpecial(): bool
    {
        return ($this->analyze() !== null);
    }
}
