<?php

/**
 * This file is part of the Outsanity IP Analysis package.
 *
 * (c) Doug Harple <dharple@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Outsanity\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Outsanity\IpAnalysis\IpAnalysis;

/**
 * Tests the IP analysis class as well as the loaded rules.
 */
class IpAnalysisTest extends TestCase
{

    /**
     * Returns the entire data set.
     *
     * @return array
     */
    public function getData(): array
    {
        return [

            // localhost: basic tests
            [
                'ip'             => '127.0.0.1',
                'loopback'       => true,
                'special'        => true,
            ],
            [
                'ip'             => '::1',
                'loopback'       => true,
                'special'        => true,
            ],

            // localhost: confirm we're checking the entire /8
            [
                'ip'             => '127.0.0.53',
                'loopback'       => true,
                'special'        => true,
            ],

            // localhost: confirm that rules written out in long form work, too

            [
                'ip'             => '0:0:0:0:0:0:0:1',
                'loopback'       => true,
                'special'        => true,
            ],

            // local: basic tests
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

            // private: basic tests
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
                'ip'             => 'fd11:1111:1111::1',
                'privateNetwork' => true,
                'special'        => true,
            ],

            // private: confirm we're checking the entire /16

            [
                'ip'             => '192.168.254.1',
                'privateNetwork' => true,
                'special'        => true,
            ],

            // documentation: basic tests

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

            // multicast: basic tests

            [
                'ip'             => '224.0.1.1',
                'global'         => false,
                'multicast'      => true,
                'special'        => true,
            ],
            [
                'ip'             => 'ff00::101',
                'global'         => false,
                'multicast'      => true,
                'special'        => true,
            ],

            // global: Google DNS

            [
                'ip'             => '8.8.8.8',
                'global'         => true,
            ],
            [
                'ip'             => '2001:4860:4860::8888',
                'global'         => true,
            ],

            // global: other public DNS that share first octets with non-global blocks
            // source: https://public-dns.info/nameservers.txt

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

        ];
    }

    /**
     * Builds the test data for testing isDocumentation()
     *
     * @return array
     */
    public function getDocumentationData(): array
    {
        return $this->getFilteredData('documentation');
    }

    /**
     * Filters getData() into a set for a specific test.
     *
     * @param string $field The field to pull from the dataset.
     *
     * @return array
     */
    public function getFilteredData(string $field): array
    {
        $data = $this->getData();
        return array_map(function ($row) use ($field) {
            return [$row['ip'], $row[$field] ?? false];
        }, $data);
    }

    /**
     * Builds the test data for testing isGlobal()
     *
     * @return array
     */
    public function getGlobalData(): array
    {
        return $this->getFilteredData('global');
    }

    /**
     * Builds the test data for testing isLocalNetwork()
     *
     * @return array
     */
    public function getLocalNetworkData(): array
    {
        return $this->getFilteredData('localNetwork');
    }

    /**
     * Builds the test data for testing isLoopback()
     *
     * @return array
     */
    public function getLoopbackData(): array
    {
        return $this->getFilteredData('loopback');
    }

    /**
     * Builds the test data for testing isMulticast()
     *
     * @return array
     */
    public function getMulticastData(): array
    {
        return $this->getFilteredData('multicast');
    }

    /**
     * Builds the test data for testing isPrivateNetwork()
     *
     * @return array
     */
    public function getPrivateNetworkData(): array
    {
        return $this->getFilteredData('privateNetwork');
    }

    /**
     * Builds the test data for testing isSpecial()
     *
     * @return array
     */
    public function getSpecialData(): array
    {
        return $this->getFilteredData('special');
    }

    /**
     * Tests isDocumentation().
     *
     * @dataProvider getDocumentationData
     *
     * @param string $ip            The IP to test.
     * @param bool   $documentation The expected value.
     *
     * @return void
     */
    public function testDocumentation(string $ip, bool $documentation): void
    {
        $analyzer = new IpAnalysis($ip);
        $this->assertSame($documentation, $analyzer->isDocumentation());
    }

    /**
     * Tests isGlobal().
     *
     * @dataProvider getGlobalData
     *
     * @param string $ip     The IP to test.
     * @param bool   $global The expected value.
     *
     * @return void
     */
    public function testGlobal(string $ip, bool $global): void
    {
        $analyzer = new IpAnalysis($ip);
        $this->assertSame($global, $analyzer->isGlobal());
    }

    /**
     * Tests isLocalNetwork().
     *
     * @dataProvider getLocalNetworkData
     *
     * @param string $ip           The IP to test.
     * @param bool   $localNetwork The expected value.
     *
     * @return void
     */
    public function testLocalNetwork(string $ip, bool $localNetwork): void
    {
        $analyzer = new IpAnalysis($ip);
        $this->assertSame($localNetwork, $analyzer->isLocalNetwork());
    }

    /**
     * Tests isLoopback().
     *
     * @dataProvider getLoopbackData
     *
     * @param string $ip       The IP to test.
     * @param bool   $loopback The expected value.
     *
     * @return void
     */
    public function testLoopback(string $ip, bool $loopback): void
    {
        $analyzer = new IpAnalysis($ip);
        $this->assertSame($loopback, $analyzer->isLoopback());
    }

    /**
     * Tests isMulticast().
     *
     * @dataProvider getMulticastData
     *
     * @param string $ip        The IP to test.
     * @param bool   $multicast The expected value.
     *
     * @return void
     */
    public function testMulticast(string $ip, bool $multicast): void
    {
        $analyzer = new IpAnalysis($ip);
        $this->assertSame($multicast, $analyzer->isMulticast());
    }

    /**
     * Tests isPrivateNetwork().
     *
     * @dataProvider getPrivateNetworkData
     *
     * @param string $ip             The IP to test.
     * @param bool   $privateNetwork The expected value.
     *
     * @return void
     */
    public function testPrivateNetwork(string $ip, bool $privateNetwork): void
    {
        $analyzer = new IpAnalysis($ip);
        $this->assertSame($privateNetwork, $analyzer->isPrivateNetwork());
    }

    /**
     * Tests isSpecial().
     *
     * @dataProvider getSpecialData
     *
     * @param string $ip      The IP to test.
     * @param bool   $special The expected value.
     *
     * @return void
     */
    public function testSpecial(string $ip, bool $special): void
    {
        $analyzer = new IpAnalysis($ip);
        $this->assertSame($special, $analyzer->isSpecial());
    }
}
