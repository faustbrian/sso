<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when an ID token does not target the configured client audience.
 *
 * Audience validation happens after token parsing and signature verification
 * but before the resolved identity is trusted. This exception represents the
 * case where the token was minted for a different relying party, which would
 * make accepting it a cross-client trust violation.
 *
 * Keeping this failure isolated lets higher-level login code and operators
 * distinguish mis-targeted tokens from other claim problems such as issuer,
 * nonce, or time-based validation failures.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidOidcAudienceException extends OidcException
{
    /**
     * Create an exception for a token with an unexpected audience claim.
     *
     * Used when the configured provider client ID is absent from the token's
     * audience values and the token therefore cannot be treated as intended
     * for this package instance.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.oidc.errors.invalid_audience'));
    }
}
