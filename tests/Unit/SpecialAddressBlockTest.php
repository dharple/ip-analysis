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
use PHPUnit\Framework\Attributes\DataProvider;
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
    public static function getBooleanData(): array
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
    public static function getNullableBooleanData(): array
    {
        return array_merge(
            static::getBooleanData(),
            static::getNullableData()
        );
    }

    /**
     * Returns a test set for nullable data
     *
     * @return array
     */
    public static function getNullableData(): array
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
    public static function getNullableStringData(): array
    {
        return array_merge(
            static::getStringData(),
            static::getNullableData()
        );
    }

    /**
     * Returns a test set for strings
     *
     * @return array
     */
    public static function getStringData(): array
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
    public static function getTypeData(): array
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
     * @param mixed   $original The original string.
     * @param ?string $expected The expected output.
     *
     * @return void
     */
    #[DataProvider('getNullableStringData')]
    public function testSetAddressBlock($original, ?string $expected)
    {
        $block = new SpecialAddressBlock();
        $block->setAddressBlock($original);
        $this->assertEquals($expected, $block->getAddressBlock());
    }

    /**
     * Test setAllocationDate
     *
     * @param mixed   $original The original string.
     * @param ?string $expected The expected output.
     *
     * @return void
     */
    #[DataProvider('getNullableStringData')]
    public function testSetAllocationDate($original, ?string $expected)
    {
        $block = new SpecialAddressBlock();
        $block->setAllocationDate($original);
        $this->assertEquals($expected, $block->getAllocationDate());
    }

    /**
     * Test setDestination
     *
     * @param mixed $original The original string.
     * @param ?bool $expected The expected output.
     *
     * @return void
     */
    #[DataProvider('getNullableBooleanData')]
    public function testSetDestination($original, ?bool $expected)
    {
        $block = new SpecialAddressBlock();
        $block->setDestination($original);
        $this->assertEquals($expected, $block->getDestination());
    }

    /**
     * Test setForwardable
     *
     * @param mixed $original The original string.
     * @param ?bool $expected The expected output.
     *
     * @return void
     */
    #[DataProvider('getNullableBooleanData')]
    public function testSetForwardable($original, ?bool $expected)
    {
        $block = new SpecialAddressBlock();
        $block->setForwardable($original);
        $this->assertEquals($expected, $block->getForwardable());
    }

    /**
     * Test setGloballyReachable
     *
     * @param mixed $original The original string.
     * @param ?bool $expected The expected output.
     *
     * @return void
     */
    #[DataProvider('getNullableBooleanData')]
    public function testSetGloballyReachable($original, ?bool $expected)
    {
        $block = new SpecialAddressBlock();
        $block->setGloballyReachable($original);
        $this->assertEquals($expected, $block->getGloballyReachable());
    }

    /**
     * Test setName
     *
     * @param mixed   $original The original string.
     * @param ?string $expected The expected output.
     *
     * @return void
     */
    #[DataProvider('getNullableStringData')]
    public function testSetName($original, ?string $expected)
    {
        $block = new SpecialAddressBlock();
        $block->setName($original);
        $this->assertEquals($expected, $block->getName());
    }

    /**
     * Test setReservedByProtocol
     *
     * @param mixed $original The original string.
     * @param ?bool $expected The expected output.
     *
     * @return void
     */
    #[DataProvider('getNullableBooleanData')]
    public function testSetReservedByProtocol($original, ?bool $expected)
    {
        $block = new SpecialAddressBlock();
        $block->setReservedByProtocol($original);
        $this->assertEquals($expected, $block->getReservedByProtocol());
    }

    /**
     * Test setRfc
     *
     * @param mixed   $original The original string.
     * @param ?string $expected The expected output.
     *
     * @return void
     */
    #[DataProvider('getNullableStringData')]
    public function testSetRfc($original, ?string $expected)
    {
        $block = new SpecialAddressBlock();
        $block->setRfc($original);
        $this->assertEquals($expected, $block->getRfc());
    }

    /**
     * Test setSource
     *
     * @param mixed $original The original string.
     * @param ?bool $expected The expected output.
     *
     * @return void
     */
    #[DataProvider('getNullableBooleanData')]
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
     * @param mixed   $original The original string.
     * @param ?string $expected The expected output.
     *
     * @return void
     */
    #[DataProvider('getNullableStringData')]
    public function testSetTerminationDate($original, ?string $expected)
    {
        $block = new SpecialAddressBlock();
        $block->setTerminationDate($original);
        $this->assertEquals($expected, $block->getTerminationDate());
    }

    /**
     * Test setType
     *
     * @param mixed   $original The original string.
     * @param ?string $expected The expected output.
     *
     * @return void
     *
     * @throws Exception This test should never throw an Exception.
     */
    #[DataProvider('getTypeData')]
    public function testSetType($original, ?string $expected)
    {
        $block = new SpecialAddressBlock();
        $block->setType($original);
        $this->assertEquals($expected, $block->getType());
    }

    /**
     * Test setType with invalid data
     *
     * @param mixed   $original The original string.
     * @param ?string $expected The expected output.
     *
     * @return void
     *
     * @noinspection PhpUnusedParameterInspection
     */
    #[DataProvider('getStringData')]
    public function testSetTypeWithInvalidData($original, ?string $expected)
    {
        $block = new SpecialAddressBlock();

        $this->expectException('Exception');
        $block->setType($original);
    }
}
