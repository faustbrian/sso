<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when SAML validation cannot obtain any trusted signing certificate.
 *
 * The package raises this after metadata import, provider settings inspection,
 * or signature verification setup determines that there is no certificate
 * material available to validate an incoming assertion. It represents a
 * provider-configuration failure rather than an issue with a specific user
 * login attempt.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class MissingSamlSigningCertificatesException extends SamlException
{
    /**
     * Create an exception for providers that expose no verification certificates.
     *
     * This is used during configuration validation and runtime signature
     * checks when the package cannot establish a trust store for the provider.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.saml.errors.missing_signing_certificates'));
    }
}
