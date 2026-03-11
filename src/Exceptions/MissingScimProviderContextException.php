<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when a SCIM controller executes without authenticated provider context.
 *
 * SCIM requests in this package are expected to pass through middleware that
 * validates the bearer token and attaches the resolved provider record to the
 * request attributes. This exception signals a broken pipeline invariant:
 * controller code is running without the provider context required to scope
 * provisioning operations and audit events.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class MissingScimProviderContextException extends ScimException
{
    /**
     * Create an exception for requests missing the SCIM provider attribute.
     *
     * Callers use this when request handling has already entered the SCIM
     * controller layer, which makes the absence of provider context a package
     * wiring failure rather than a user-facing authorization error.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.scim.errors.provider_context_missing'));
    }
}
