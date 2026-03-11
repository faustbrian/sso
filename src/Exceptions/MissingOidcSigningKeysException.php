<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when the provider exposes no usable OIDC signing keys.
 *
 * After loading the provider's JWKS, the package filters for keys that can
 * actually verify ID tokens. If none remain, the provider may be publishing an
 * empty set, a non-signing key set, or keys outside the expected type. This
 * exception captures that trust-material failure before a runtime login
 * attempts to validate a token signature.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class MissingOidcSigningKeysException extends OidcException
{
    /**
     * Create an exception for providers without verifiable signing material.
     *
     * This is used both in administrative configuration checks and in runtime
     * validation paths so the package reports the same root cause whenever a
     * provider cannot furnish a signing key that matches package expectations.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.oidc.errors.missing_signing_keys'));
    }
}
