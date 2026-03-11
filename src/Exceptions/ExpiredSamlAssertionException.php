<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when a SAML assertion has passed its `NotOnOrAfter` validity window.
 *
 * The package raises this after XML parsing, signature checks, and request
 * binding validation, once it reaches temporal condition enforcement. It makes
 * it clear that the assertion was structurally valid but no longer trustworthy
 * for establishing a new login session.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class ExpiredSamlAssertionException extends SamlException
{
    /**
     * Create an exception for an assertion that is no longer time-valid.
     *
     * This factory centralizes the translated package message so SAML callback
     * failures report expiry in a single, predictable way.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.saml.errors.assertion_expired'));
    }
}
