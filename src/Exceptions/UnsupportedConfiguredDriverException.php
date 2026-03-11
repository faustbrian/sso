<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when configured driver bindings do not resolve to valid SSO strategies.
 *
 * This exception is used during service provider bootstrapping, while the
 * package is turning configured driver class names into concrete strategy
 * instances. It signals a package configuration defect rather than a runtime
 * provider lookup failure.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class UnsupportedConfiguredDriverException extends ConfigurationException
{
    /**
     * Create an exception for a configured driver whose class is unsupported.
     *
     * @param  string $driver The configuration key for the invalid strategy binding
     * @return self   Exception instance describing the unsupported driver
     */
    public static function forDriver(string $driver): self
    {
        return new self(self::translate('sso::sso.system.errors.unsupported_driver', ['driver' => $driver]));
    }
}
