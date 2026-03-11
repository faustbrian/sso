<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when the package cannot produce a signed or encodable SAML AuthnRequest.
 *
 * This failure belongs to the outbound SAML redirect phase. It covers both
 * low-level signing failures and request-encoding problems that prevent the
 * package from generating a trustworthy login initiation payload for the
 * identity provider.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class UnsignedAuthnRequestException extends SamlException
{
    /**
     * Create an exception for an AuthnRequest that could not be signed or encoded.
     *
     * @return self Exception instance with the package's translated error message
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.saml.errors.unsigned_authn_request'));
    }
}
