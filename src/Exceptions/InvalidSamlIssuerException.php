<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Exception thrown when a SAML response issuer does not match the expected
 * provider issuer configured for validation.
 *
 * This exception represents a hard trust failure after the package has already
 * extracted identity data from the response. It keeps issuer enforcement
 * explicit and catchable so operators can distinguish provider-identity
 * mismatches from lower-level XML, signature, or routing failures.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidSamlIssuerException extends SamlException
{
    /**
     * Create an exception for a response signed by or attributed to an
     * unexpected issuer.
     *
     * The translated message is emitted only when issuer validation is enabled
     * and the configured or metadata-derived issuer does not match the
     * response, signalling a provider trust misconfiguration rather than a
     * generic response-validation problem.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.saml.errors.invalid_issuer'));
    }
}
