<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when an ID token nonce does not match the originating login attempt.
 *
 * Nonce validation ties the callback token to the browser session state that
 * initiated the authorization-code flow. This exception signals replay or
 * cross-request mismatch conditions where the token may be structurally valid
 * but cannot be safely associated with the current interactive login attempt.
 *
 * It exists as its own type because nonce mismatches usually point to session
 * integrity or replay issues rather than upstream provider metadata problems.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidOidcNonceException extends OidcException
{
    /**
     * Create an exception for a token whose nonce claim fails request binding.
     *
     * Used once the token has been parsed and its required claims are present,
     * but the nonce value no longer matches the request-scoped value stored by
     * the package for the active login transaction.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.oidc.errors.invalid_nonce'));
    }
}
