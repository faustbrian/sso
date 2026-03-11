<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when an OIDC token declares a signing algorithm the package does not verify.
 *
 * The OIDC strategy supports a bounded set of asymmetric RSA algorithms for ID
 * token verification. This exception marks the point where token headers were
 * structurally valid but requested a cryptographic algorithm outside that
 * supported verification set.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class UnsupportedOidcAlgorithmException extends OidcException
{
    /**
     * Create an exception for an unsupported token signing algorithm.
     *
     * @param  string $algorithm The JWT `alg` header value that could not be mapped
     * @return self   Exception instance describing the unsupported algorithm
     */
    public static function forAlgorithm(string $algorithm): self
    {
        return new self(self::translate('sso::sso.oidc.errors.unsupported_algorithm', ['algorithm' => $algorithm]));
    }
}
