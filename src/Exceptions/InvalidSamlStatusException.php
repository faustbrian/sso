<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when a SAML response reports a non-success protocol status.
 *
 * The package validates response status before it trusts assertions, issuer
 * values, or attributes. This exception therefore captures an identity
 * provider's explicit rejection or failure response rather than a parsing or
 * cryptographic defect in the response document itself.
 *
 * Keeping status failures separate makes it easier to understand whether the
 * login was rejected by the identity provider or by local package validation.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidSamlStatusException extends SamlException
{
    /**
     * Create an exception for a non-success SAML status code.
     *
     * Used when the response status is anything other than the SAML success
     * constant required for the package to continue assertion validation.
     *
     * @return self Exception describing the invalid SAML status
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.saml.errors.invalid_status'));
    }
}
