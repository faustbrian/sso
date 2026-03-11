<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when a multi-audience OIDC token lacks a matching authorized party.
 *
 * OIDC allows tokens to contain multiple audiences, but in that case the
 * package expects the `azp` claim to identify the relying party actually meant
 * to use the token. This exception separates that specific authorization
 * constraint failure from broader audience or issuer mismatches.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidAuthorizedPartyException extends OidcException
{
    /**
     * Create an exception for a token whose `azp` claim does not match the client.
     *
     * This factory documents that the package failed at the multi-audience
     * claim validation stage rather than during parsing or signature checks.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.oidc.errors.invalid_authorized_party'));
    }
}
