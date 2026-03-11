<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when an OIDC ID token is presented before its validity window opens.
 *
 * This exception is raised after the JWT has already been parsed and its
 * signature accepted, but the `nbf` claim still places the token in the
 * future relative to the current clock plus package leeway. It therefore
 * signals a temporal trust failure rather than malformed token structure.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class OidcTokenNotYetValidException extends OidcException
{
    /**
     * Create an exception for ID tokens whose `nbf` claim is still in the future.
     *
     * Callers use this after claim extraction when the token cannot yet be
     * treated as trustworthy for authentication.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.oidc.errors.token_not_yet_valid'));
    }
}
