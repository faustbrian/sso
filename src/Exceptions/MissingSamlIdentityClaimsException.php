<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when a SAML response omits the issuer or subject needed to identify a user.
 *
 * Successful XML parsing and signature validation are not enough for the
 * package to produce a resolved identity. The response must also contain the
 * core issuer and subject values that link the assertion to a trusted identity
 * provider and a concrete remote principal. This exception marks the point
 * where those required claims were absent even though earlier protocol gates
 * may already have passed.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class MissingSamlIdentityClaimsException extends SamlException
{
    /**
     * Create an exception for assertions missing the minimum identity payload.
     *
     * Callers use this after extracting issuer and subject values from the
     * assertion so downstream account resolution does not have to reason about
     * partially populated identities.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.saml.errors.missing_identity_claims'));
    }
}
