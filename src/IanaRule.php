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

use Symfony\Component\Serializer\Annotation\SerializedName;

/**
 * Defines an IANA rule from a Special-Purpose Address Registry.
 */
class IanaRule
{
    /**
     * The address block in CIDR notation.
     *
     * @SerializedName("Address Block")
     * @var ?string
     */
    protected $addressBlock;

    /**
     * The date that the rule was allocated.
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
     * The type of rule.
     *   IANA - Defined by the IANA Special-Purpose Address Registry
     *   Other - Defined by some other source.
     *
     * @var ?string
     */
    protected $type = 'IANA';

    /**
     * Instantiates a new IanaRule out of a var_export()'d copy.
     *
     * @param array $data The output of var_export().
     *
     * @return IanaRule
     *
     * @throws \Exception Thrown when a setter is missing.
     */
    public static function __set_state(array $data): IanaRule
    {
        $rule = new IanaRule();

        foreach ($data as $field => $value) {
            if ($field === 'type' || $value === null) {
                continue;
            }

            $method = 'set' . ucfirst($field);
            if (!method_exists($rule, $method)) {
                throw new \Exception(sprintf('method "%s" does not exist', $method));
            }

            call_user_func([$rule, $method], $value);
        }

        return $rule;
    }

    /**
     * Checks a boolean for use in a property.  Converts "True" and "False" to
     * true and false, respectively.
     *
     * @param mixed $in The data to check.
     *
     * @return bool
     */
    protected function checkBool($in): bool
    {
        return filter_var($this->removeAnnotations($in), FILTER_VALIDATE_BOOLEAN);
    }

    /**
     * Checks a string for use in a property.
     *
     * @param mixed $in The data to check.
     *
     * @return string
     */
    protected function checkString($in): string
    {
        return (string) $this->removeAnnotations($in);
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
     * Returns the date that the rule was allocated.
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
     * Returns the type of rule.
     *
     * @return ?string
     */
    public function getType(): ?string
    {
        return $this->type;
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
     * @return IanaRule
     */
    public function setAddressBlock(?string $addressBlock): self
    {
        $this->addressBlock = $this->checkString($addressBlock);
        return $this;
    }

    /**
     * Sets the date that the rule was allocated.
     *
     * @param ?string $allocationDate The data to set.
     *
     * @return IanaRule
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
     * @return IanaRule
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
     * @return IanaRule
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
     * @return IanaRule
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
     * @return IanaRule
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
     * @return IanaRule
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
     * @return IanaRule
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
     * @return IanaRule
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
     * @return IanaRule
     */
    public function setTerminationDate(?string $terminationDate): self
    {
        $this->terminationDate = $this->checkString($terminationDate);
        return $this;
    }

    /**
     * Sets the type of rule.
     *
     * @param ?string $type The data to set.
     *
     * @return IanaRule
     */
    public function setType(?string $type): self
    {
        $this->type = $this->checkString($type);
        return $this;
    }
}
