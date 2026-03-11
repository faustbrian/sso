<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when the discovery document exposes an issuer field with the wrong type.
 *
 * The package accepts discovery metadata as the canonical source for OIDC
 * endpoints and, optionally, issuer expectations. This exception captures a
 * structurally invalid discovery document where the issuer key exists but is
 * not a string, making the metadata unsafe to trust or persist.
 *
 * Separating this from generic discovery-response failures preserves the
 * distinction between a totally malformed document and a specific contract
 * violation in an otherwise decoded discovery payload.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidOidcDiscoveryIssuerException extends OidcException
{
    /**
     * Create an exception for a discovery document with an invalid issuer value.
     *
     * Returned when the provider includes an issuer key but the associated
     * value cannot be treated as the canonical issuer string expected by the
     * rest of the OIDC validation pipeline.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.oidc.errors.invalid_discovery_issuer'));
    }
}
