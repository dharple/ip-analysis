<?php

namespace Outsanity\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Outsanity\IpAnalysis\IpAnalysis;

class IpAnalysisTest extends TestCase
{

    public function getData()
    {
        return [
            // host only
            ['127.0.0.1',       IpAnalysis::SCOPE_HOST,    true],
            ['127.0.0.53',      IpAnalysis::SCOPE_HOST,    true],

            // subnet only
            ['169.254.13.1',    IpAnalysis::SCOPE_SUBNET,  true],

            // private networks
            ['10.0.0.93',       IpAnalysis::SCOPE_PRIVATE, true],
            ['172.16.0.21',     IpAnalysis::SCOPE_PRIVATE, true],
            ['192.168.1.1',     IpAnalysis::SCOPE_PRIVATE, true],
            ['192.168.254.1',   IpAnalysis::SCOPE_PRIVATE, true],

            // public DNS
            //
            // source: https://public-dns.info/nameservers.txt
            //
            // some famous, some randomly chosen based on first octet matching
            // a reserved subnet
            ['169.239.202.202', IpAnalysis::SCOPE_GLOBAL,  false],
            ['172.98.193.42',   IpAnalysis::SCOPE_GLOBAL,  false],
            ['192.195.100.4',   IpAnalysis::SCOPE_GLOBAL,  false],
            ['209.244.0.3',     IpAnalysis::SCOPE_GLOBAL,  false],
            ['8.8.8.8',         IpAnalysis::SCOPE_GLOBAL,  false],
            ['9.9.9.9',         IpAnalysis::SCOPE_GLOBAL,  false],
        ];
    }

    /**
     * @dataProvider getData
     */
    public function testReserved($ip, $scope, $reserved)
    {
        $analyzer = new IpAnalysis($ip);
        $this->assertSame($reserved, $analyzer->isReserved());
        $this->assertSame($scope, $analyzer->getScope());
    }
}
