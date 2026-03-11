<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when the provider's JSON Web Key Set payload cannot be consumed.
 *
 * This exception marks the trust-material loading stage of the OIDC flow.
 * The package raises it when the remote JWKS endpoint responds with a payload
 * that is not an array of keys, which means later signature verification
 * cannot proceed against a deterministic set of public keys.
 *
 * It exists as a separate type from other discovery and token exceptions so
 * callers can distinguish upstream signing-key corruption from broader OIDC
 * metadata failures or claim-validation failures.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidJwksResponseException extends OidcException
{
    /**
     * Create an exception for an unusable JWKS response payload.
     *
     * Returned when the package successfully reaches the configured JWKS
     * endpoint but the decoded response body cannot be treated as the expected
     * key collection used for token signature verification.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.oidc.errors.invalid_jwks_response'));
    }
}
