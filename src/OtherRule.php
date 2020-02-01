<?php

namespace Outsanity\IpAnalysis;

use Symfony\Component\Serializer\Annotation\SerializedName;

class OtherRule extends IanaRule
{
    /**
     * @var string
     */
    protected $type = 'Other';
}
