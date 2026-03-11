<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Configuration;

use Cline\SSO\Exceptions\InvalidDriverClassConfigurationException;
use Illuminate\Support\Facades\Config;

use function array_map;
use function is_string;

/**
 * Resolves the map of configured strategy classes keyed by provider driver.
 *
 * Persisted provider records store a lightweight driver name such as `oidc` or
 * `saml`, while runtime authentication flows need a concrete strategy class
 * that can build redirects, validate callbacks, and map remote metadata. This
 * reader is the bridge between those persisted identifiers and the class map
 * consumed by the strategy resolver.
 *
 * Validation happens here so bootstrapping fails early when configuration is
 * malformed. Downstream services can therefore assume that every configured
 * driver points to a non-empty class string instead of defensively rechecking
 * the same invariants during a login request.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class DriverConfiguration
{
    /**
     * Return all configured provider drivers keyed by their persisted name.
     *
     * Invalid or empty entries are rejected immediately so the service provider
     * can fail during bootstrapping instead of leaving a broken driver mapping
     * to be discovered only after a user starts an authentication flow.
     *
     * @return array<string, string>
     */
    public function all(): array
    {
        /** @var array<string, string> */
        return array_map(
            static function (mixed $value): string {
                if (!is_string($value) || $value === '') {
                    throw InvalidDriverClassConfigurationException::forValue();
                }

                return $value;
            },
            Config::array('sso.drivers', []),
        );
    }
}
