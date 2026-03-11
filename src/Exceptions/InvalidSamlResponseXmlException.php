<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when an inbound SAML response cannot be parsed as trusted XML.
 *
 * This exception marks the earliest failure boundary in SAML callback
 * processing after transport-level decoding succeeds. It indicates that the
 * package received a SAMLResponse payload, but DOM parsing could not produce a
 * document suitable for status, signature, and assertion validation.
 *
 * Surfacing this as its own type keeps malformed XML distinct from later
 * protocol failures such as invalid status codes, missing signatures, or
 * audience mismatches.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidSamlResponseXmlException extends SamlException
{
    /**
     * Create an exception for a SAML response with invalid XML structure.
     *
     * Used when the package cannot load the decoded response into a DOM
     * document, which means no later SAML trust checks can run safely.
     *
     * @return self Exception describing the invalid response document
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.saml.errors.invalid_response_xml'));
    }
}
