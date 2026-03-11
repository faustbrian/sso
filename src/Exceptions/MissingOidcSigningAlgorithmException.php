<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when OIDC metadata or token headers do not declare a signing algorithm.
 *
 * The strategy needs an explicit algorithm to choose the correct verifier and
 * to ensure the token or key material matches an allowed signature family.
 * This exception therefore marks the point where validation cannot continue
 * because cryptographic intent was omitted from otherwise parseable input.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class MissingOidcSigningAlgorithmException extends OidcException
{
    /**
     * Create an exception for OIDC inputs that omit the expected algorithm.
     *
     * Raised during token-header inspection or verification-key resolution so
     * callers can treat missing cryptographic metadata as a distinct failure
     * from unsupported algorithms or invalid signatures.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.oidc.errors.missing_signing_algorithm'));
    }
}
