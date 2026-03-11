<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when an OIDC ID token is already outside its accepted lifetime.
 *
 * This exception marks the time-based validation stage after parsing,
 * signature verification, and claim extraction have already succeeded. It
 * exists so callers can distinguish expired credentials from malformed tokens
 * or issuer/audience mismatches when diagnosing failed login attempts.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class ExpiredOidcTokenException extends OidcException
{
    /**
     * Create an exception for an ID token whose expiration time has elapsed.
     *
     * The resulting message mirrors the package translation key used for OIDC
     * token lifetime failures so browser login rejection paths stay consistent
     * with the rest of the protocol-specific error handling.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.oidc.errors.expired_token'));
    }
}
