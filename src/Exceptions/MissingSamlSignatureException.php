<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when a SAML response arrives without any usable XML signature.
 *
 * This exception marks the point where the SAML strategy has successfully
 * parsed the inbound response document but cannot continue trust validation
 * because neither the top-level response nor the assertion carries a
 * verifiable signature. It is only raised when the provider configuration
 * requires signed assertions, which makes it an explicit trust-boundary
 * failure rather than a generic XML parsing problem.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class MissingSamlSignatureException extends SamlException
{
    /**
     * Create an exception for responses that omit the required XML signature.
     *
     * Callers use this once SAML parsing has succeeded and signature discovery
     * has determined that no signed element is present where package policy
     * requires one.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.saml.errors.missing_signature'));
    }
}
