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
 * Base exception for SAML response parsing, trust validation, and metadata handling.
 *
 * Concrete subclasses represent the explicit gates a SAML response must pass
 * before the package treats an identity as trusted: XML decoding, signature
 * presence and verification, request binding, audience and issuer enforcement,
 * timing checks, and metadata completeness. This base gives higher layers a
 * single catch target for SAML-specific failures while preserving granular
 * exception types for protocol-stage diagnostics.
 *
 * @author Brian Faust <brian@cline.sh>
 */
abstract class SamlException extends RuntimeException implements SsoException
{
    use ResolvesExceptionMessage;
}
