<?php

namespace Outsanity\IpAnalysis;

use Symfony\Component\Serializer\Annotation\SerializedName;

class IanaRule
{
    /**
     * @SerializedName("Address Block")
     *
     * @var string
     */
     protected $addressBlock;

    /**
     * @SerializedName("Allocation Date")
     *
     * @var string
     */
     protected $allocationDate;

    /**
     * @SerializedName("Destination")
     *
     * @var bool
     */
     protected $destination;

    /**
     * @SerializedName("Forwardable")
     *
     * @var bool
     */
     protected $forwardable;

    /**
     * @SerializedName("Globally Reachable")
     *
     * @var bool
     */
     protected $globallyReachable;

    /**
     * @SerializedName("Name")
     *
     * @var string
     */
     protected $name;

    /**
     * @SerializedName("Reserved-by-Protocol")
     *
     * @var bool
     */
     protected $reservedByProtocol;

    /**
     * @SerializedName("RFC")
     *
     * @var string
     */
     protected $rfc;

    /**
     * @SerializedName("Source")
     *
     * @var bool
     */
     protected $source;

    /**
     * @SerializedName("Termination Date")
     *
     * @var string
     */
     protected $terminationDate;

    public static function __set_state(array $data)
    {
        $rule = new IanaRule();

        foreach ($data as $field => $value) {
            $method = 'set' . ucfirst($field);
            if (!method_exists($rule, $method)) {
                throw new \Exception(sprintf('method "%s" does not exist', $method));
            }

            call_user_func([$rule, $method], $value);
        }

        return $rule;
    }

    protected function checkBool($in): bool
    {
        return filter_var($this->removeAnnotations($in), FILTER_VALIDATE_BOOLEAN);
    }

    protected function checkString(string $in): string
    {
        return $this->removeAnnotations($in);
    }

    public function getAddressBlock(): string
    {
        return $this->addressBlock;
    }

    public function getAllocationDate(): string
    {
        return $this->allocationDate;
    }

    public function getDestination(): ?bool
    {
        return $this->destination;
    }

    public function getForwardable(): ?bool
    {
        return $this->forwardable;
    }

    public function getGloballyReachable(): ?bool
    {
        return $this->globallyReachable;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getReservedByProtocol(): ?bool
    {
        return $this->reservedByProtocol;
    }

    public function getRfc(): string
    {
        return $this->rfc;
    }

    public function getSource(): bool
    {
        return $this->source;
    }

    public function getTerminateDate(): string
    {
        return $this->terminationDate;
    }

    protected function removeAnnotations($in)
    {
        return is_scalar($in) ? preg_replace('/ *\[[0-9]+\]/', '', $in) : $in;
    }

    public function setAddressBlock(string $addressBlock): self
    {
        $this->addressBlock = $this->checkString($addressBlock);

        return $this;
    }

    public function setAllocationDate(string $allocationDate): self
    {
        $this->allocationDate = $this->checkString($allocationDate);

        return $this;
    }

    public function setDestination($destination): self
    {
        $this->destination = $this->checkBool($destination);

        return $this;
    }

    public function setForwardable($forwardable): self
    {
        $this->forwardable = $this->checkBool($forwardable);

        return $this;
    }

    public function setGloballyReachable($globallyReachable): self
    {
        $this->globallyReachable = $this->checkBool($globallyReachable);

        return $this;
    }

    public function setName(string $name): self
    {
        $this->name = $this->checkString($name);

        return $this;
    }

    public function setReservedByProtocol($reservedByProtocol): self
    {
        $this->reservedByProtocol = $this->checkBool($reservedByProtocol);

        return $this;
    }

    public function setRfc(string $rfc): self
    {
        $this->rfc = $this->checkString($rfc);

        return $this;
    }

    public function setSource($source): self
    {
        $this->source = $this->checkBool($source);

        return $this;
    }

    public function setTerminationDate(string $terminationDate): self
    {
        $this->terminationDate = $this->checkString($terminationDate);

        return $this;
    }
}
