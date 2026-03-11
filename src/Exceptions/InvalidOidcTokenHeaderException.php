<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when the JWT header segment cannot be decoded into usable metadata.
 *
 * The package reads the token header before selecting a signer or resolving a
 * verification key from the JWKS set. This exception marks failures where the
 * header segment is missing, undecodable, or not an associative structure that
 * can safely expose fields like `alg`, `typ`, or `kid`.
 *
 * The dedicated type distinguishes early JWT parsing failures from broader
 * token-structure failures where the compact token format itself is invalid.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidOidcTokenHeaderException extends OidcException
{
    /**
     * Create an exception for an invalid JWT header payload.
     *
     * Returned when the token header cannot provide the metadata required to
     * choose a verification algorithm and locate the correct signing key.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.oidc.errors.invalid_token_header'));
    }
}
