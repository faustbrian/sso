<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when a validated token's issuer does not match the trusted provider issuer.
 *
 * Issuer comparison is one of the final claim-level trust checks in the OIDC
 * pipeline. This exception indicates that the token may have been minted by a
 * different authority than the configured provider, even if the token shape
 * and signature were otherwise acceptable.
 *
 * A dedicated issuer exception keeps identity-provider mismatch failures
 * distinct from discovery bootstrap problems and from missing issuer
 * configuration on providers that require strict issuer enforcement.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidOidcIssuerException extends OidcException
{
    /**
     * Create an exception for a token whose issuer claim cannot be trusted.
     *
     * Returned when issuer validation is enabled and the resolved issuer value
     * fails to match the configured or discovered issuer expectation.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.oidc.errors.invalid_issuer'));
    }
}
