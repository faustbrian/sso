<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when the package detects a present but unverifiable SAML signature.
 *
 * This exception represents a trust failure later in SAML response validation
 * than missing-signature or missing-certificate errors. The response contains
 * signed elements, but none of the configured or discovered certificates can
 * verify the embedded signature material.
 *
 * Treating this as a dedicated exception type lets callers and maintainers
 * distinguish cryptographic verification failures from XML parsing, issuer
 * mismatches, or response-binding errors.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidSamlSignatureException extends SamlException
{
    /**
     * Create an exception for an invalid SAML signature.
     *
     * Used after the package finds signature elements but cannot verify them
     * against any trusted certificate for the provider.
     *
     * @return self Exception describing the failed signature verification
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.saml.errors.invalid_signature'));
    }
}
