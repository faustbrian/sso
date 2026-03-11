<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when the configured SCIM route middleware stack contains invalid
 * entries.
 *
 * This exception is raised while the package reads route configuration during
 * boot. It protects SCIM route registration from empty or non-string middleware
 * values that would otherwise create a partially configured API surface.
 *
 * The dedicated type distinguishes SCIM route boot failures from interactive
 * SSO route configuration errors and from later request-time SCIM failures.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidScimRouteMiddlewareException extends ConfigurationException
{
    /**
     * Create an exception for an invalid SCIM middleware entry.
     *
     * Used when a configured SCIM middleware item is empty or not representable
     * as a Laravel middleware alias/class string.
     *
     * @return self Exception describing the invalid SCIM middleware entry
     */
    public static function forValue(): self
    {
        return new self('SSO SCIM route middleware entries must be non-empty strings.');
    }
}
