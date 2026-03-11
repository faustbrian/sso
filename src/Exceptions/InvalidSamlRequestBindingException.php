<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Exception thrown when a SAML response cannot be tied back to the original
 * authentication request issued by the package.
 *
 * The package tracks login attempts with request IDs and rejects assertions
 * whose `InResponseTo` binding is missing or mismatched. This exception marks
 * that replay-protection and correlation boundary, making it clear that the
 * failure is about request/response pairing rather than assertion contents.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidSamlRequestBindingException extends SamlException
{
    /**
     * Create an exception for a response whose request binding is absent or
     * does not match the stored login attempt.
     *
     * The resulting message helps operators trace callback failures back to
     * broken request correlation, expired login sessions, or identity-provider
     * responses posted against the wrong browser flow.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.saml.errors.invalid_request_binding'));
    }
}
