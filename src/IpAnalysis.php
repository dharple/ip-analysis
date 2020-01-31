<?php

namespace Outsanity\IpAnalysis;

use Symfony\Component\HttpFoundation\IpUtils;

class IpAnalysis
{
    protected $ianaRule;
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

    public function __construct($ip)
    {
        $this->ip = $ip;
    }

    protected function analyze(): ?IanaRule
    {
        if (!$this->processed) {
            $ianaRules = include dirname(__DIR__) . '/data/iana-ipv4-special-registry-1.php';

            foreach ($ianaRules as $ianaRule) {
                if (IpUtils::checkIp($this->ip, $ianaRule->getAddressBlock())) {
                    $this->ianaRule = $ianaRule;
                    break;
                }
            }
        }

        return $this->ianaRule;
    }

    public function isGlobal(): bool
    {
        $ianaRule = $this->analyze();
        return $ianaRule ? $ianaRule->getGloballyReachable() : true;
    }

    public function isLoopback(): bool
    {
        $ianaRule = $this->analyze();
        return ($ianaRule !== null && in_array($ianaRule->getName(), static::NAME_LOOPBACK));
    }

    public function isLocalNetwork(): bool
    {
        $ianaRule = $this->analyze();
        return ($ianaRule !== null && in_array($ianaRule->getName(), static::NAME_LOCAL));
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
