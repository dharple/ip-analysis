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

use Exception;
use Outsanity\IpAnalysis\SpecialAddressBlock;
use PHPUnit\Framework\TestCase;

/**
 * Tests SpecialAddressBlock
 */
class SpecialAddressBlockTest extends TestCase
{

    /**
     * Returns a test set for booleans
     *
     * @return array
     */
    public function getBooleanData(): array
    {
        return [
            // true and true-like values
            [ 'True',      true ],
            [ 'True [1]',  true ],
            [ 'True [0]',  true ],
            [ true,        true ],
            [ 1,           true ],
            [ 'TRUE',      true ],
            [ 'yes',       true ],

            // false and false-like values
            [ 'False',     false ],
            [ 'False [4]', false ],
            [ 'False [0]', false ],
            [ false,       false ],
            [ 0,           false ],
            [ 'FALSE',     false ],
            [ 'no',        false ],
        ];
    }

    /**
     * Returns a test set for nullable booleans
     *
     * @return array
     */
    public function getNullableBooleanData(): array
    {
        return array_merge(
            $this->getBooleanData(),
            $this->getNullableData()
        );
    }

    /**
     * Returns a test set for nullable data
     *
     * @return array
     */
    public function getNullableData(): array
    {
        return [
            // special null values
            [ 'null',      null ],
            [ null,        null ],
            [ 'N/A',       null ],
            [ 'N/A [6]',   null ],
        ];
    }

    /**
     * Returns a test set for nullable strings
     *
     * @return array
     */
    public function getNullableStringData(): array
    {
        return array_merge(
            $this->getStringData(),
            $this->getNullableData()
        );
    }

    /**
     * Returns a test set for strings
     *
     * @return array
     */
    public function getStringData(): array
    {
        return [
            // basic strings
            [ 'lorem ipsum',            'lorem ipsum'        ],
            [ 'lorem [2] ipsum',        'lorem ipsum'        ],
            [ '[RFC1149] [3]',          '[RFC1149]'          ],
            [ '[RFC1149][RFC2324][42]', '[RFC1149][RFC2324]' ],
        ];
    }

    /**
     * Returns a test set for block type
     *
     * @return array
     */
    public function getTypeData(): array
    {
        return [
            [ SpecialAddressBlock::TYPE_IANA,  SpecialAddressBlock::TYPE_IANA  ],
            [ SpecialAddressBlock::TYPE_OTHER, SpecialAddressBlock::TYPE_OTHER ],
            [ null,                            null,                           ],
        ];
    }

    /**
     * Test setAddressBlock
     *
     * @dataProvider getNullableStringData
     *
     * @param mixed   $original The original string.
     * @param ?string $expected The expected output.
     *
     * @return void
     */
    public function testSetAddressBlock($original, ?string $expected)
    {
        $block = new SpecialAddressBlock();
        $block->setAddressBlock($original);
        $this->assertEquals($expected, $block->getAddressBlock());
    }

    /**
     * Test setAllocationDate
     *
     * @dataProvider getNullableStringData
     *
     * @param mixed   $original The original string.
     * @param ?string $expected The expected output.
     *
     * @return void
     */
    public function testSetAllocationDate($original, ?string $expected)
    {
        $block = new SpecialAddressBlock();
        $block->setAllocationDate($original);
        $this->assertEquals($expected, $block->getAllocationDate());
    }

    /**
     * Test setDestination
     *
     * @dataProvider getNullableBooleanData
     *
     * @param mixed $original The original string.
     * @param ?bool $expected The expected output.
     *
     * @return void
     */
    public function testSetDestination($original, ?bool $expected)
    {
        $block = new SpecialAddressBlock();
        $block->setDestination($original);
        $this->assertEquals($expected, $block->getDestination());
    }

    /**
     * Test setForwardable
     *
     * @dataProvider getNullableBooleanData
     *
     * @param mixed $original The original string.
     * @param ?bool $expected The expected output.
     *
     * @return void
     */
    public function testSetForwardable($original, ?bool $expected)
    {
        $block = new SpecialAddressBlock();
        $block->setForwardable($original);
        $this->assertEquals($expected, $block->getForwardable());
    }

    /**
     * Test setGloballyReachable
     *
     * @dataProvider getNullableBooleanData
     *
     * @param mixed $original The original string.
     * @param ?bool $expected The expected output.
     *
     * @return void
     */
    public function testSetGloballyReachable($original, ?bool $expected)
    {
        $block = new SpecialAddressBlock();
        $block->setGloballyReachable($original);
        $this->assertEquals($expected, $block->getGloballyReachable());
    }

    /**
     * Test setName
     *
     * @dataProvider getNullableStringData
     *
     * @param mixed   $original The original string.
     * @param ?string $expected The expected output.
     *
     * @return void
     */
    public function testSetName($original, ?string $expected)
    {
        $block = new SpecialAddressBlock();
        $block->setName($original);
        $this->assertEquals($expected, $block->getName());
    }

    /**
     * Test setReservedByProtocol
     *
     * @dataProvider getNullableBooleanData
     *
     * @param mixed $original The original string.
     * @param ?bool $expected The expected output.
     *
     * @return void
     */
    public function testSetReservedByProtocol($original, ?bool $expected)
    {
        $block = new SpecialAddressBlock();
        $block->setReservedByProtocol($original);
        $this->assertEquals($expected, $block->getReservedByProtocol());
    }

    /**
     * Test setRfc
     *
     * @dataProvider getNullableStringData
     *
     * @param mixed   $original The original string.
     * @param ?string $expected The expected output.
     *
     * @return void
     */
    public function testSetRfc($original, ?string $expected)
    {
        $block = new SpecialAddressBlock();
        $block->setRfc($original);
        $this->assertEquals($expected, $block->getRfc());
    }

    /**
     * Test setSource
     *
     * @dataProvider getNullableBooleanData
     *
     * @param mixed $original The original string.
     * @param ?bool $expected The expected output.
     *
     * @return void
     */
    public function testSetSource($original, ?bool $expected)
    {
        $block = new SpecialAddressBlock();
        $block->setSource($original);
        $this->assertEquals($expected, $block->getSource());
    }

    /**
     * Test __set_state with invalid data
     *
     * @return void
     */
    public function testSetState()
    {
        $this->expectException('Exception');
        SpecialAddressBlock::__set_state(['invalid_field' => 'invalid value']);
    }

    /**
     * Test setTerminationDate
     *
     * @dataProvider getNullableStringData
     *
     * @param mixed   $original The original string.
     * @param ?string $expected The expected output.
     *
     * @return void
     */
    public function testSetTerminationDate($original, ?string $expected)
    {
        $block = new SpecialAddressBlock();
        $block->setTerminationDate($original);
        $this->assertEquals($expected, $block->getTerminationDate());
    }

    /**
     * Test setType
     *
     * @dataProvider getTypeData
     *
     * @param mixed   $original The original string.
     * @param ?string $expected The expected output.
     *
     * @return void
     *
     * @throws Exception This test should never throw an Exception.
     */
    public function testSetType($original, ?string $expected)
    {
        $block = new SpecialAddressBlock();
        $block->setType($original);
        $this->assertEquals($expected, $block->getType());
    }

    /**
     * Test setType with invalid data
     *
     * @dataProvider getStringData
     *
     * @param mixed   $original The original string.
     * @param ?string $expected The expected output.
     *
     * @return void
     *
     * @noinspection PhpUnusedParameterInspection
     */
    public function testSetTypeWithInvalidData($original, ?string $expected)
    {
        $block = new SpecialAddressBlock();

        $this->expectException('Exception');
        $block->setType($original);
    }
}
