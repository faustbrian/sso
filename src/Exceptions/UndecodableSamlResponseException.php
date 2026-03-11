<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when an inbound SAML response payload cannot be base64 decoded.
 *
 * This failure occurs near the start of SAML callback processing, before XML
 * parsing or signature validation can begin. It indicates the identity
 * provider returned a malformed or corrupted `SAMLResponse` value that cannot
 * represent a valid SAML protocol document.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class UndecodableSamlResponseException extends SamlException
{
    /**
     * Create an exception for an unreadable SAML response payload.
     *
     * @return self Exception instance with the package's translated message
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.saml.errors.undecodable_response'));
    }
}
