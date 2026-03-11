<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when a configured package extension key points to an invalid class.
 *
 * The service provider uses named configuration keys for principal resolvers,
 * repositories, SCIM adapters, and other extension points. This exception is
 * used when the configuration entry itself is empty or when an unknown key is
 * requested while resolving those bindings during package bootstrap.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidConfiguredContractException extends ConfigurationException
{
    /**
     * Create an exception for an invalid or empty configured contract key.
     *
     * @param  string $key Configuration key being resolved at boot time
     * @return self   Exception describing the invalid package contract entry
     */
    public static function forKey(string $key): self
    {
        return new self(self::translate('sso::sso.system.errors.invalid_contract_class', ['key' => $key]));
    }
}
