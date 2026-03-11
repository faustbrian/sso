<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Drivers;

use Cline\SSO\Contracts\SsoStrategy;
use Cline\SSO\Data\SsoProviderRecord;
use Cline\SSO\Exceptions\UnknownSsoDriverException;

/**
 * Resolves the concrete strategy that should handle a provider record.
 *
 * Provider rows persist a driver name, while the service provider binds the
 * corresponding protocol strategy instances. This resolver is the narrow
 * bridge between those two worlds: it converts persisted driver identifiers
 * into concrete implementations at runtime without forcing the provider record
 * itself to know about the container.
 *
 * Resolution is intentionally strict. An unknown driver is treated as a
 * configuration error rather than an unsupported runtime branch, which keeps
 * protocol selection deterministic and easier to diagnose.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class SsoStrategyResolver
{
    /**
     * @param array<string, SsoStrategy> $strategies Strategies keyed by persisted provider driver name
     */
    public function __construct(
        private array $strategies,
    ) {}

    /**
     * Return the strategy responsible for the provider's configured driver.
     *
     * An invalid driver is treated as a configuration error and results in an
     * exception instead of falling back to a partially compatible strategy.
     * Callers therefore receive either a protocol handler that fully supports
     * the provider's driver or a clear failure.
     */
    public function resolve(SsoProviderRecord $provider): SsoStrategy
    {
        if (!isset($this->strategies[$provider->driver])) {
            throw UnknownSsoDriverException::forDriver($provider->driver);
        }

        return $this->strategies[$provider->driver];
    }
}
