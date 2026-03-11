<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when the OIDC token endpoint response does not include an ID token.
 *
 * The package's OIDC flow treats the ID token as the authoritative source of
 * identity claims and signature-verifiable authentication state. If the token
 * exchange returns access-token data without an accompanying ID token, the
 * login cannot advance into claim validation or identity resolution and must
 * fail immediately.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class MissingIdTokenException extends OidcException
{
    /**
     * Create an exception for token responses missing the primary ID token.
     *
     * Raised directly after the authorization-code exchange so callers can
     * distinguish an incomplete token payload from later failures such as
     * malformed JWT headers, invalid audiences, or issuer mismatches.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.oidc.errors.missing_id_token'));
    }
}
