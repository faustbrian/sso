<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when an OIDC token header omits the signing key identifier.
 *
 * The package resolves verification material from the provider's JWKS by
 * matching the token header's `kid` to a concrete signing key. Without that
 * identifier, signature verification cannot be tied to a specific remote key,
 * so token parsing must stop before any trust is placed in the payload.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class MissingOidcKeyIdentifierException extends OidcException
{
    /**
     * Create an exception for tokens that cannot be mapped to a JWKS entry.
     *
     * This distinguishes a structurally readable JWT header from one that is
     * still unusable for verification because the header lacks the key
     * selection data required to locate the provider's signing certificate.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.oidc.errors.missing_key_identifier'));
    }
}
