<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Exceptions;

/**
 * @author Brian Faust <brian@cline.sh>
 */
final class MissingSamlElementIdException extends SamlTestFixtureException
{
    public static function create(): self
    {
        return new self('The SAML element is missing an ID attribute.');
    }
}
