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
                'global'         => false,
                'localNetwork'   => false,
                'loopback'       => true,
                'privateNetwork' => false,
                'special'        => true,
            ],
            [
                'ip'             => '127.0.0.53',
                'global'         => false,
                'localNetwork'   => false,
                'loopback'       => true,
                'privateNetwork' => false,
                'special'        => true,
            ],

            // link local (subnet) only
            [
                'ip'             => '169.254.13.1',
                'global'         => false,
                'localNetwork'   => true,
                'loopback'       => false,
                'privateNetwork' => false,
                'special'        => true,
            ],

            // private networks
            [
                'ip'             => '10.0.0.93',
                'global'         => false,
                'localNetwork'   => false,
                'loopback'       => false,
                'privateNetwork' => true,
                'special'        => true,
            ],
            [
                'ip'             => '172.16.0.21',
                'global'         => false,
                'localNetwork'   => false,
                'loopback'       => false,
                'privateNetwork' => true,
                'special'        => true,
            ],
            [
                'ip'             => '192.168.1.1',
                'global'         => false,
                'localNetwork'   => false,
                'loopback'       => false,
                'privateNetwork' => true,
                'special'        => true,
            ],
            [
                'ip'             => '192.168.254.1',
                'global'         => false,
                'localNetwork'   => false,
                'loopback'       => false,
                'privateNetwork' => true,
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
                'localNetwork'   => false,
                'loopback'       => false,
                'privateNetwork' => false,
                'special'        => false,
            ],
            [
                'ip'             => '172.98.193.42',
                'global'         => true,
                'localNetwork'   => false,
                'loopback'       => false,
                'privateNetwork' => false,
                'special'        => false,
            ],
            [
                'ip'             => '192.195.100.4',
                'global'         => true,
                'localNetwork'   => false,
                'loopback'       => false,
                'privateNetwork' => false,
                'special'        => false,
            ],
            [
                'ip'             => '209.244.0.3',
                'global'         => true,
                'localNetwork'   => false,
                'loopback'       => false,
                'privateNetwork' => false,
                'special'        => false,
            ],
            [
                'ip'             => '8.8.8.8',
                'global'         => true,
                'localNetwork'   => false,
                'loopback'       => false,
                'privateNetwork' => false,
                'special'        => false,
            ],
            [
                'ip'             => '9.9.9.9',
                'global'         => true,
                'localNetwork'   => false,
                'loopback'       => false,
                'privateNetwork' => false,
                'special'        => false,
            ],
        ];
    }

    public function getFilteredData($field)
    {
        $data = $this->getData();
        return array_map(function($row) use ($field) {
            if (!array_key_exists($field, $row)) {
                throw new \Exception(sprintf('Could not find field "%s" in row with ip "%s"', $field, $row['ip']));
            }

            return [$row['ip'], $row[$field]];
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

    public function getPrivateNetworkData()
    {
        return $this->getFilteredData('privateNetwork');
    }

    public function getSpecialData()
    {
        return $this->getFilteredData('special');
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
