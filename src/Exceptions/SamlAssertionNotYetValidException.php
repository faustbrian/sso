<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when a SAML assertion's validity window has not started yet.
 *
 * This exception is emitted after XML parsing, signature checks, and response
 * binding have already succeeded. It isolates the specific temporal failure
 * where the assertion's `NotBefore` condition still lies in the future,
 * allowing operators to distinguish clock-skew and issuer-timing problems from
 * other SAML validation failures.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class SamlAssertionNotYetValidException extends SamlException
{
    /**
     * Create an exception for assertions whose `NotBefore` condition is unmet.
     *
     * Callers use this when the assertion is structurally valid but cannot yet
     * be trusted as an authentication statement.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.saml.errors.assertion_not_yet_valid'));
    }
}
