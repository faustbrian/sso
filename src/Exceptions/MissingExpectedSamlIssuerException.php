<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when SAML issuer validation is required but no expected issuer exists.
 *
 * SAML responses may be checked against a configured issuer on the provider
 * record or an issuer imported from metadata. This exception captures the
 * state where issuer validation is enabled but neither source produced a
 * trusted comparison value, making it unsafe to accept assertions that claim
 * to come from an identity provider.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class MissingExpectedSamlIssuerException extends SamlException
{
    /**
     * Create an exception for issuer enforcement without a reference issuer.
     *
     * Callers raise this before accepting assertions so administrative
     * validation and runtime login processing fail with the same explicit cause
     * when issuer checking has been requested but the provider setup is
     * incomplete.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.saml.errors.missing_expected_issuer'));
    }
}
