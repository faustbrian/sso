<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

use RuntimeException;

/**
 * Base exception for OIDC discovery, token exchange, and ID-token validation.
 *
 * Concrete exceptions extending this base represent distinct failure points in
 * the OpenID Connect login lifecycle: remote discovery responses, JWKS
 * material resolution, header and claim validation, issuer enforcement, and
 * time-based trust checks. The abstraction exists so callers can catch
 * protocol-specific failures broadly without collapsing every OIDC error into
 * an undifferentiated runtime exception.
 *
 * @author Brian Faust <brian@cline.sh>
 */
abstract class OidcException extends RuntimeException implements SsoException
{
    use ResolvesExceptionMessage;
}
