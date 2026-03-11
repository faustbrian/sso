<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when required keys are absent from the OIDC discovery document.
 *
 * Discovery is the step that supplies the authorization endpoint, token
 * endpoint, and JWKS location the rest of the OIDC strategy depends on. This
 * exception identifies a discovery payload that was structurally decoded but
 * still unusable because a specific mandatory field was missing or empty.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class MissingOidcDiscoveryKeyException extends OidcException
{
    /**
     * Create an exception for a specific missing discovery-document key.
     *
     * The key name is included in the translated message so operators can see
     * exactly which portion of the upstream metadata is incomplete and why the
     * provider cannot proceed through authorization, token exchange, or key
     * resolution.
     *
     * @param  string $key Required discovery-document field that was missing
     * @return self   Exception instance describing the missing field
     */
    public static function forKey(string $key): self
    {
        return new self(self::translate('sso::sso.oidc.errors.missing_discovery_key', ['key' => $key]));
    }
}
