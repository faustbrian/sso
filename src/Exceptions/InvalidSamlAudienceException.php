<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Exception thrown when a SAML assertion targets an audience other than the
 * service provider configured in the package.
 *
 * Audience validation is one of the final trust gates in SAML response
 * processing. This exception indicates that the assertion may be well-formed,
 * signed, and temporally valid, but it was not issued for this application,
 * so the package refuses to convert it into a trusted local identity.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidSamlAudienceException extends SamlException
{
    /**
     * Create an exception for an assertion whose audience restriction excludes
     * the configured service provider entity ID.
     *
     * The resulting message describes a trust-boundary violation rather than a
     * low-level XML parsing problem, helping operators distinguish misrouted or
     * misconfigured identity-provider responses from malformed documents.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.saml.errors.invalid_audience'));
    }
}
