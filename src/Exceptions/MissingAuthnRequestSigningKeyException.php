<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when the package is asked to sign a SAML AuthnRequest without an
 * available private signing key.
 *
 * This exception belongs to outbound SAML request generation rather than
 * inbound assertion validation. It signals that provider configuration demands
 * signed redirect payloads, but the package cannot satisfy that requirement
 * because the client secret/private key material is missing.
 *
 * Keeping this distinct from general signing failures helps operators separate
 * misconfiguration of request-signing credentials from cryptographic runtime
 * failures during signing itself.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class MissingAuthnRequestSigningKeyException extends SamlException
{
    /**
     * Create an exception for a missing AuthnRequest signing key.
     *
     * Used when SAML request signing is enabled but no private key is
     * available to produce the outbound signature.
     *
     * @return self Exception describing the missing signing key material
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.saml.errors.missing_authn_request_signing_key'));
    }
}
