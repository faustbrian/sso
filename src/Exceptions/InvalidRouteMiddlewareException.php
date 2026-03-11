<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Exception thrown when the configured browser-route middleware stack contains
 * an invalid entry.
 *
 * Interactive SSO routes are registered from package configuration during
 * service-provider boot. This exception protects that registration phase by
 * rejecting empty or non-string middleware definitions early, so the package
 * never exposes partially configured login endpoints with ambiguous middleware
 * behavior.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidRouteMiddlewareException extends ConfigurationException
{
    /**
     * Create an exception for an invalid interactive-route middleware value.
     *
     * The factory is used while normalizing configured middleware arrays for
     * the browser SSO route group. It signals that the host application's
     * configuration must be corrected before route registration can proceed.
     */
    public static function forValue(): self
    {
        return new self('SSO route middleware entries must be non-empty strings.');
    }
}
