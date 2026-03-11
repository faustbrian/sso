<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Exception thrown when an OIDC ID token advertises an unexpected `typ` value.
 *
 * The package accepts tokens only when the header either omits `typ` or
 * declares the canonical JWT type. This exception marks the stage where token
 * parsing has already succeeded but the header metadata still fails the
 * package's trust checks, preventing partially compatible bearer artifacts
 * from proceeding to signature or claim validation.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidOidcTokenTypeException extends OidcException
{
    /**
     * Create an exception for an ID token with a non-JWT header type.
     *
     * This factory is used after the JOSE header is decoded but before the
     * token is treated as a valid OpenID Connect identity token. The resulting
     * message explains that the provider returned a structurally parseable
     * token whose declared type does not match the package's expected JWT flow.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.oidc.errors.invalid_token_type'));
    }
}
