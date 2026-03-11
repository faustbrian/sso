<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when OIDC token verification cannot resolve a usable signing key.
 *
 * This exception represents the boundary between successful metadata/token
 * parsing and actual cryptographic verification. The package raises it when
 * the JWK set does not contain a matching key or when the matched key cannot
 * be converted into a public key suitable for signature validation.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class UnresolvedOidcSigningKeyException extends OidcException
{
    /**
     * Create an exception for a missing or unusable OIDC signing key.
     *
     * @return self Exception instance with the translated key-resolution error
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.oidc.errors.unresolved_signing_key'));
    }
}
