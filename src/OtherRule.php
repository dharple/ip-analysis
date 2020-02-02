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
 * Defines a rule from a different RFC.
 */
class OtherRule extends IanaRule
{
    /**
     * {@inheritdoc}
     *
     * @var ?string
     */
    protected $type = 'Other';
}
