<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when outbound SAML request signing is enabled without a private key.
 *
 * This exception captures a configuration mismatch between provider settings
 * and available credentials. The package only throws it when request signing
 * has been explicitly enabled, which means it points to a broken operator
 * setup rather than an optional capability being absent.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class MissingSamlSigningKeyException extends SamlException
{
    /**
     * Create an exception for providers missing the configured signing key.
     *
     * Callers use this while validating provider configuration before
     * attempting to build or sign an outbound AuthnRequest.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.saml.errors.missing_signing_key'));
    }
}
