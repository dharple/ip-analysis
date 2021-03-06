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

use Exception;
use Symfony\Component\Serializer\Annotation\SerializedName;

/**
 * Defines a special address block, either from one of the IANA Special-Purpose
 * Address registries, or another source.
 */
class SpecialAddressBlock
{
    /**
     * This type indicates that the block came from one of the Special-Purpose
     * Address Registries.
     *
     * @var string
     */
    public const TYPE_IANA  = 'IANA';

    /**
     * This type indicates that the block came from somewhere else.
     *
     * @var string
     */
    public const TYPE_OTHER = 'Other';

    /**
     * The address block in CIDR notation.
     *
     * @SerializedName("Address Block")
     * @var ?string
     */
    protected $addressBlock;

    /**
     * The date that the block was allocated.
     *
     * @SerializedName("Allocation Date")
     * @var ?string
     */
    protected $allocationDate;

    /**
     * Whether or not an address in the block may be used as a destination address.
     *
     * @SerializedName("Destination")
     * @var ?bool
     */
    protected $destination;

    /**
     * Whether or not an address in the block may be forwarded.
     *
     * @SerializedName("Forwardable")
     * @var ?bool
     */
    protected $forwardable;

    /**
     * Whether or not an address in the block is globally reachable.
     *
     * @SerializedName("Globally Reachable")
     * @var ?bool
     */
    protected $globallyReachable;

    /**
     * The name of the address block.
     *
     * Not unique.
     *
     * @SerializedName("Name")
     * @var ?string
     */
    protected $name;

    /**
     * Whether or not the address block is reserved by the protocol itself.
     *
     * @SerializedName("Reserved-by-Protocol")
     * @var ?bool
     */
    protected $reservedByProtocol;

    /**
     * The RFC that allocates the address block.
     *
     * @SerializedName("RFC")
     * @var ?string
     */
    protected $rfc;

    /**
     * Whether or not an address in the block may be used as a source address.
     *
     * @SerializedName("Source")
     * @var ?bool
     */
    protected $source;

    /**
     * The termination date of the address block's allocation.
     *
     * @SerializedName("Termination Date")
     * @var ?string
     */
    protected $terminationDate;

    /**
     * The source type of block.
     *   IANA - Defined by the IANA Special-Purpose Address Registry
     *   Other - Defined by some other source.
     *
     * @var ?string
     */
    protected $type;

    /**
     * Instantiates a new SpecialAddressBlock out of a var_export()'d copy.
     *
     * @param array $data The output of var_export().
     *
     * @return SpecialAddressBlock
     *
     * @throws Exception Thrown when a setter is missing.
     */
    public static function __set_state(array $data): SpecialAddressBlock
    {
        $block = new SpecialAddressBlock();

        foreach ($data as $field => $value) {
            if ($field === 'type' || $value === null) {
                continue;
            }

            $method = 'set' . ucfirst($field);
            if (!method_exists($block, $method)) {
                throw new Exception(sprintf('method "%s" does not exist', $method));
            }

            call_user_func([$block, $method], $value);
        }

        return $block;
    }

    /**
     * Checks a boolean for use in a property.  Converts "True" and "False" to
     * true and false, respectively.  "null" or "n/a" become null.
     *
     * @param mixed $in The data to check.
     *
     * @return ?bool
     */
    protected function checkBool($in): ?bool
    {
        $work = $this->removeAnnotations($in);
        if ($this->isNull($work)) {
            return null;
        }

        return filter_var($work, FILTER_VALIDATE_BOOLEAN);
    }

    /**
     * Checks a string for use in a property.
     *
     * @param mixed $in The data to check.
     *
     * @return string
     */
    protected function checkString($in): ?string
    {
        $work = $this->removeAnnotations($in);
        return $this->isNull($work) ? null : $work;
    }

    /**
     * Returns the address block in CIDR notation.
     *
     * @return ?string
     */
    public function getAddressBlock(): ?string
    {
        return $this->addressBlock;
    }

    /**
     * Returns the date that the block was allocated.
     *
     * @return ?string
     */
    public function getAllocationDate(): ?string
    {
        return $this->allocationDate;
    }

    /**
     * Returns whether or not an address in the block may be used as a
     * destination address.
     *
     * @return ?bool
     */
    public function getDestination(): ?bool
    {
        return $this->destination;
    }

    /**
     * Returns whether or not an address in the block may be forwarded.
     *
     * @return ?bool
     */
    public function getForwardable(): ?bool
    {
        return $this->forwardable;
    }

    /**
     * Returns whether or not an address in the block is globally reachable.
     *
     * @return ?bool
     */
    public function getGloballyReachable(): ?bool
    {
        return $this->globallyReachable;
    }

    /**
     * Returns the name of the address block.
     *
     * @return ?string
     */
    public function getName(): ?string
    {
        return $this->name;
    }

    /**
     * Returns whether or not the address block is reserved by the protocol
     * itself.
     *
     * @return ?bool
     */
    public function getReservedByProtocol(): ?bool
    {
        return $this->reservedByProtocol;
    }

    /**
     * Returns the RFC that defines this address block.
     *
     * @return ?string
     */
    public function getRfc(): ?string
    {
        return $this->rfc;
    }

    /**
     * Returns whether or not an address in the block may be used as a source
     * address.
     *
     * @return ?bool
     */
    public function getSource(): ?bool
    {
        return $this->source;
    }

    /**
     * Returns the termination date of the address block's allocation.
     *
     * @return ?string
     */
    public function getTerminationDate(): ?string
    {
        return $this->terminationDate;
    }

    /**
     * Returns the source type of block.
     *
     * @return ?string
     */
    public function getType(): ?string
    {
        return $this->type;
    }

    /**
     * Checks to see if the address is an IPV4 address.
     *
     * @return bool
     */
    public function isIpv4(): bool
    {
        return !$this->isIpv6();
    }

    /**
     * Checks to see if the address is an IPV6 address.
     *
     * @return bool
     */
    public function isIpv6(): bool
    {
        return substr_count($this->addressBlock, ':') > 1;
    }

    /**
     * Checks to see if a value is null-like.  'null', 'N/A', and null are all
     * null-like.
     *
     * @param mixed $in Checks to see whether a value is null-like.
     *
     * @return bool
     */
    protected function isNull($in): bool
    {
        if ($in === null) {
            return true;
        }

        return (is_scalar($in) && in_array(strtolower(trim($in)), ['null', 'n/a']));
    }

    /**
     * Removes footnote annotations from a variable.
     *
     * Removes instances of [1], [2], [n], but leaves [RFC1149], [RFC2324],
     * [RFCyyz] alone.
     *
     * @param mixed $in The data to remove annotations from.
     *
     * @return mixed
     */
    protected function removeAnnotations($in)
    {
        return is_scalar($in) ? preg_replace('/ *\[[0-9]+\]/', '', $in) : $in;
    }

    /**
     * Sets the address block (in CIDR notation).
     *
     * @param ?string $addressBlock The data to set.
     *
     * @return SpecialAddressBlock
     */
    public function setAddressBlock(?string $addressBlock): self
    {
        $this->addressBlock = $this->checkString($addressBlock);
        return $this;
    }

    /**
     * Sets the date that the block was allocated.
     *
     * @param ?string $allocationDate The data to set.
     *
     * @return SpecialAddressBlock
     */
    public function setAllocationDate(?string $allocationDate): self
    {
        $this->allocationDate = $this->checkString($allocationDate);
        return $this;
    }

    /**
     * Sets whether or not an address in the block may be used as a
     * destination address.
     *
     * @param mixed $destination The data to set.
     *
     * @return SpecialAddressBlock
     */
    public function setDestination($destination): self
    {
        $this->destination = $this->checkBool($destination);
        return $this;
    }

    /**
     * Sets whether or not an address in the block may be used as a
     * destination address.
     *
     * @param mixed $forwardable The data to set.
     *
     * @return SpecialAddressBlock
     */
    public function setForwardable($forwardable): self
    {
        $this->forwardable = $this->checkBool($forwardable);
        return $this;
    }

    /**
     * Sets whether or not an address in the block is globally reachable.
     *
     * @param mixed $globallyReachable The data to set.
     *
     * @return SpecialAddressBlock
     */
    public function setGloballyReachable($globallyReachable): self
    {
        $this->globallyReachable = $this->checkBool($globallyReachable);
        return $this;
    }

    /**
     * Sets the name of this address block.
     *
     * @param ?string $name The data to set.
     *
     * @return SpecialAddressBlock
     */
    public function setName(?string $name): self
    {
        $this->name = $this->checkString($name);
        return $this;
    }

    /**
     * Sets whether or not an address in the block is reserved by the protocol itself.
     *
     * @param mixed $reservedByProtocol The data to set.
     *
     * @return SpecialAddressBlock
     */
    public function setReservedByProtocol($reservedByProtocol): self
    {
        $this->reservedByProtocol = $this->checkBool($reservedByProtocol);
        return $this;
    }

    /**
     * Sets the RFC that defines this address block.
     *
     * @param ?string $rfc The data to set.
     *
     * @return SpecialAddressBlock
     */
    public function setRfc(?string $rfc): self
    {
        $this->rfc = $this->checkString($rfc);
        return $this;
    }

    /**
     * Sets whether or not an address in the block may be used as a
     * source address.
     *
     * @param mixed $source The data to set.
     *
     * @return SpecialAddressBlock
     */
    public function setSource($source): self
    {
        $this->source = $this->checkBool($source);
        return $this;
    }

    /**
     * Sets the termination date of the address block's allocation.
     *
     * @param ?string $terminationDate The data to set.
     *
     * @return SpecialAddressBlock
     */
    public function setTerminationDate(?string $terminationDate): self
    {
        $this->terminationDate = $this->checkString($terminationDate);
        return $this;
    }

    /**
     * Sets the source type of the block.
     *
     * @param ?string $type The data to set.  One of static::TYPE_IANA or
     *                      static::TYPE_OTHER.
     *
     * @return SpecialAddressBlock
     *
     * @throws Exception Thrown when an invalid type is passed.
     */
    public function setType(?string $type): self
    {
        if ($type !== null && $type !== static::TYPE_IANA && $type !== static::TYPE_OTHER) {
            throw new Exception('invalid type');
        }

        $this->type = $type;

        return $this;
    }
}
