<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when the configured driver class map contains an empty or invalid entry.
 *
 * Driver configuration is read during package boot to build the strategy map
 * used for SSO provider resolution. This exception prevents the package from
 * accepting blank class names and deferring a broken driver definition until a
 * real login request tries to resolve the strategy.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidDriverClassConfigurationException extends ConfigurationException
{
    /**
     * Create an exception for a malformed driver class configuration value.
     *
     * The driver map must contain only non-empty class strings so service
     * provider registration can build a reliable protocol strategy registry.
     */
    public static function forValue(): self
    {
        return new self('SSO driver classes must be non-empty strings.');
    }
}
