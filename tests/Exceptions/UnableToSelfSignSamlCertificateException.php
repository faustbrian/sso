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
final class UnableToSelfSignSamlCertificateException extends SamlTestFixtureException
{
    public static function create(): self
    {
        return new self('Unable to self-sign the SAML certificate.');
    }
}
