<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when the SAML callback does not contain a response payload.
 *
 * The browser callback is expected to include a `SAMLResponse` parameter that
 * can be decoded and validated against the pending login attempt. When that
 * parameter is absent or empty, the package cannot even begin XML parsing or
 * trust checks, so the flow fails at the earliest protocol boundary.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class MissingSamlResponseException extends SamlException
{
    /**
     * Create an exception for callback requests without a SAML response body.
     *
     * This lets the login flow distinguish transport-level absence of the
     * assertion payload from later failures such as undecodable content,
     * malformed XML, or invalid signatures.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.saml.errors.missing_response'));
    }
}
