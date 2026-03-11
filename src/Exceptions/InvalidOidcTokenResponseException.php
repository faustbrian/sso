<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when the token endpoint response cannot be treated as a valid token payload.
 *
 * This exception belongs to the authorization-code exchange stage of the OIDC
 * flow. It signals that the package successfully contacted the token endpoint
 * but the decoded response body is not the associative payload shape expected
 * for downstream access to `id_token` and related response fields.
 *
 * Isolating this failure from later token-parsing exceptions helps separate
 * transport/exchange issues from JWT-level validation problems.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidOidcTokenResponseException extends OidcException
{
    /**
     * Create an exception for an unusable token endpoint response body.
     *
     * Used when the authorization code exchange completes at the HTTP layer
     * but the returned payload cannot be treated as the token map required by
     * the package's ID token validation logic.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.oidc.errors.invalid_token_response'));
    }
}
