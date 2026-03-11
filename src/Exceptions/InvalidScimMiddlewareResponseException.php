<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when the SCIM authentication middleware pipeline returns a value that
 * is not an HTTP response.
 *
 * The package's SCIM middleware establishes provider context and then expects
 * the downstream pipeline to continue returning Symfony response objects. This
 * exception captures a broken middleware/controller contract rather than an
 * authentication failure or SCIM protocol rejection.
 *
 * By isolating that invariant breach in its own type, the package makes it
 * clear that the request pipeline itself is misconfigured.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidScimMiddlewareResponseException extends ScimException
{
    /**
     * Create an exception for a non-response returned from the SCIM pipeline.
     *
     * Used after bearer-token validation succeeds but the downstream middleware
     * stack or controller fails to return a concrete response instance.
     *
     * @return self Exception describing the middleware contract violation
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.system.errors.scim_middleware_response'));
    }
}
