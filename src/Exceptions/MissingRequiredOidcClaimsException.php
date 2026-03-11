<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when an ID token omits the claims required for a trusted identity.
 *
 * The package requires a minimum claim set before it can convert a verified
 * token into its normalized resolved-identity value object. Missing issuer,
 * subject, or nonce claims mean the token cannot be reliably tied back to the
 * provider, the subject, and the original browser session, so validation stops
 * before any account lookup or provisioning logic runs.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class MissingRequiredOidcClaimsException extends OidcException
{
    /**
     * Create an exception for ID tokens missing mandatory identity claims.
     *
     * Raised after signature validation but before claim-specific checks such
     * as issuer, audience, or nonce comparison, making it clear that the token
     * failed because essential identity data was absent rather than incorrect.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.oidc.errors.missing_required_claims'));
    }
}
