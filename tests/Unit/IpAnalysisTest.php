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
            [
                'ip'             => '127.0.0.1',
                'loopback'       => true,
                'special'        => true,
            ],
            [
                'ip'             => '127.0.0.53',
                'loopback'       => true,
                'special'        => true,
            ],
            [
                'ip'             => '::1',
                'loopback'       => true,
                'special'        => true,
            ],
            [
                'ip'             => '0:0:0:0:0:0:0:1',
                'loopback'       => true,
                'special'        => true,
            ],

            // link local (subnet) only
            [
                'ip'             => '169.254.13.1',
                'localNetwork'   => true,
                'special'        => true,
            ],
            [
                'ip'             => 'fe80::6450:6a14:93ba:de09',
                'localNetwork'   => true,
                'special'        => true,
            ],
            [
                'ip'             => 'fe80::200:1234:5678:dead',
                'localNetwork'   => true,
                'special'        => true,
            ],

            // private networks
            [
                'ip'             => '10.0.0.93',
                'privateNetwork' => true,
                'special'        => true,
            ],
            [
                'ip'             => '172.16.0.21',
                'privateNetwork' => true,
                'special'        => true,
            ],
            [
                'ip'             => '192.168.1.1',
                'privateNetwork' => true,
                'special'        => true,
            ],
            [
                'ip'             => '192.168.254.1',
                'privateNetwork' => true,
                'special'        => true,
            ],
            [
                'ip'             => 'fd11:1111:1111::1',
                'privateNetwork' => true,
                'special'        => true,
            ],
            [
                'ip'             => 'fd12:3456:dead::65',
                'privateNetwork' => true,
                'special'        => true,
            ],

            // documentation

            [
                'ip'             => '192.0.2.65',
                'documentation'  => true,
                'special'        => true,
            ],
            [
                'ip'             => '198.51.100.65',
                'documentation'  => true,
                'special'        => true,
            ],
            [
                'ip'             => '203.0.113.65',
                'documentation'  => true,
                'special'        => true,
            ],
            [
                'ip'             => '2001:db8:1:3::2',
                'documentation'  => true,
                'special'        => true,
            ],

            // multicast

            [
                'ip'             => '224.1.2.3',
                'global'         => false,
                'multicast'      => true,
                'special'        => true,
            ],
            [
                'ip'             => 'ff00:1234:5678:0:dead:2c0b:dead:0',
                'global'         => false,
                'multicast'      => true,
                'special'        => true,
            ],

            // public DNS
            //
            // source: https://public-dns.info/nameservers.txt
            //
            // some famous, some randomly chosen based on first octet matching
            // a non-global subnet
            [
                'ip'             => '169.239.202.202',
                'global'         => true,
            ],
            [
                'ip'             => '172.98.193.42',
                'global'         => true,
            ],
            [
                'ip'             => '192.195.100.4',
                'global'         => true,
            ],
            [
                'ip'             => '209.244.0.3',
                'global'         => true,
            ],
            [
                'ip'             => '8.8.8.8',
                'global'         => true,
            ],
            [
                'ip'             => '9.9.9.9',
                'global'         => true,
            ],
            [
                'ip'             => '2001:4860:4860::8888',
                'global'         => true,
            ],
            [
                'ip'             => '2001:4860:4860::8844',
                'global'         => true,
            ],

        ];
    }

    public function getDocumentationData()
    {
        return $this->getFilteredData('documentation');
    }

    public function getFilteredData($field)
    {
        $data = $this->getData();
        return array_map(function ($row) use ($field) {
            return [$row['ip'], $row[$field] ?? false];
        }, $data);
    }

    public function getGlobalData()
    {
        return $this->getFilteredData('global');
    }

    public function getLocalNetworkData()
    {
        return $this->getFilteredData('localNetwork');
    }

    public function getLoopbackData()
    {
        return $this->getFilteredData('loopback');
    }

    public function getMulticastData()
    {
        return $this->getFilteredData('multicast');
    }

    public function getPrivateNetworkData()
    {
        return $this->getFilteredData('privateNetwork');
    }

    public function getSpecialData()
    {
        return $this->getFilteredData('special');
    }

    /**
     * @dataProvider getDocumentationData
     */
    public function testDocumentation($ip, $documentation)
    {
        $analyzer = new IpAnalysis($ip);
        $this->assertSame($documentation, $analyzer->isDocumentation());
    }

    /**
     * @dataProvider getGlobalData
     */
    public function testGlobal($ip, $global)
    {
        $analyzer = new IpAnalysis($ip);
        $this->assertSame($global, $analyzer->isGlobal());
    }

    /**
     * @dataProvider getLocalNetworkData
     */
    public function testLocalNetwork($ip, $localNetwork)
    {
        $analyzer = new IpAnalysis($ip);
        $this->assertSame($localNetwork, $analyzer->isLocalNetwork());
    }

    /**
     * @dataProvider getLoopbackData
     */
    public function testLoopback($ip, $loopback)
    {
        $analyzer = new IpAnalysis($ip);
        $this->assertSame($loopback, $analyzer->isLoopback());
    }

    /**
     * @dataProvider getMulticastData
     */
    public function testMulticast($ip, $multicast)
    {
        $analyzer = new IpAnalysis($ip);
        $this->assertSame($multicast, $analyzer->isMulticast());
    }

    /**
     * @dataProvider getPrivateNetworkData
     */
    public function testPrivateNetwork($ip, $privateNetwork)
    {
        $analyzer = new IpAnalysis($ip);
        $this->assertSame($privateNetwork, $analyzer->isPrivateNetwork());
    }

    /**
     * @dataProvider getSpecialData
     */
    public function testSpecial($ip, $special)
    {
        $analyzer = new IpAnalysis($ip);
        $this->assertSame($special, $analyzer->isSpecial());
    }
}
