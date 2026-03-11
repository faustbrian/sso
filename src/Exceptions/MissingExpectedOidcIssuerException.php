<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when issuer validation is enabled but no trusted OIDC issuer exists.
 *
 * OIDC token validation can compare the token issuer either against an issuer
 * persisted on the provider record or against the issuer advertised by the
 * discovery document. This exception marks the configuration gap where issuer
 * checking is required but neither source produced a usable expected value, so
 * the login flow cannot safely decide whether an incoming token was issued by
 * the correct authorization server.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class MissingExpectedOidcIssuerException extends OidcException
{
    /**
     * Create an exception for issuer validation without an expected issuer.
     *
     * This is raised during configuration validation or token verification when
     * the provider is configured to enforce issuer matching but the package
     * could not derive a comparison value from stored settings or discovery
     * metadata.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.oidc.errors.missing_expected_issuer'));
    }
}
