<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when a persisted provider references an unregistered strategy driver.
 *
 * This exception is raised by the strategy resolver after provider lookup has
 * already succeeded but before any protocol-specific work begins. It signals
 * a mismatch between stored provider data and the strategy map registered by
 * the service provider.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class UnknownSsoDriverException extends ConfigurationException
{
    /**
     * Create an exception for a provider driver that has no resolver entry.
     *
     * @param  string $driver The persisted provider driver name that failed lookup
     * @return self   Exception instance describing the unsupported driver
     */
    public static function forDriver(string $driver): self
    {
        return new self(self::translate('sso::sso.system.errors.unsupported_driver', ['driver' => $driver]));
    }
}
