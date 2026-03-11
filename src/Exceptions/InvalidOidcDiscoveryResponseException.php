<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when the OpenID Connect discovery document cannot be treated as valid metadata.
 *
 * This exception covers the early metadata-resolution phase of the OIDC flow,
 * before any token exchange or signature verification can occur. It signals
 * that the `.well-known/openid-configuration` response could not be decoded
 * into the expected associative array structure.
 *
 * The dedicated type keeps discovery bootstrap failures distinct from
 * downstream JWKS, token, and claim-validation exceptions so configuration
 * and upstream provider issues are easier to diagnose.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidOidcDiscoveryResponseException extends OidcException
{
    /**
     * Create an exception for an unusable discovery document response.
     *
     * Used when the package reaches the discovery endpoint but the decoded
     * body cannot serve as the metadata map required to continue the OIDC
     * authorization and validation lifecycle.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.oidc.errors.invalid_discovery_response'));
    }
}
