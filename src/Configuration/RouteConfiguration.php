<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Configuration;

use Cline\SSO\Exceptions\InvalidRouteMiddlewareException;
use Cline\SSO\Exceptions\InvalidScimRouteMiddlewareException;
use Illuminate\Support\Facades\Config;

use function array_map;
use function array_values;
use function is_string;

/**
 * Reads route toggles, middleware stacks, and naming conventions.
 *
 * The package exposes two distinct HTTP surfaces with different operational
 * concerns: browser-based login routes for interactive SSO and SCIM API routes
 * for machine-to-machine provisioning. This reader keeps their enablement,
 * middleware, URI prefixes, and route names consistent so the service provider
 * can register both surfaces without needing to understand the raw config tree.
 *
 * Validation of middleware arrays happens here because malformed route config
 * should fail during application boot, not later when a request reaches a
 * partially registered route group.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class RouteConfiguration
{
    /**
     * Determine whether the interactive SSO web routes should be registered.
     *
     * When disabled, the service provider should skip the browser-login route
     * group entirely rather than registering inert endpoints.
     */
    public function enabled(): bool
    {
        return Config::boolean('sso.routes.enabled', true);
    }

    /**
     * Return the middleware stack applied to interactive SSO routes.
     *
     * Every entry is normalized to a non-empty string so route registration can
     * assume Laravel middleware names are valid before attaching them. This
     * preserves a clean separation between configuration validation and routing.
     *
     * @return array<int, string>
     */
    public function middleware(): array
    {
        return array_values(array_map(
            static function (mixed $value): string {
                if (!is_string($value) || $value === '') {
                    throw InvalidRouteMiddlewareException::forValue();
                }

                return $value;
            },
            Config::array('sso.routes.middleware', ['web']),
        ));
    }

    /**
     * Return the URI prefix for browser-facing SSO endpoints.
     *
     * The service provider uses this to group interactive login, callback, and
     * provider-selection routes under a predictable namespace.
     */
    public function prefix(): string
    {
        return Config::string('sso.routes.prefix', 'sso');
    }

    /**
     * Return the route-name prefix used for browser-facing SSO endpoints.
     *
     * Keeping the prefix configurable lets applications integrate the package
     * into an existing route naming scheme without rewriting controllers.
     */
    public function namePrefix(): string
    {
        return Config::string('sso.routes.name_prefix', 'sso.');
    }

    /**
     * Return the route name used for the provider index or chooser page.
     *
     * Applications that render a provider chooser or link into the package's
     * login flow can depend on this stable name instead of a hard-coded URI.
     */
    public function indexName(): string
    {
        return Config::string('sso.routes.index_name', 'sso.index');
    }

    /**
     * Return the route name used by the identity-provider callback endpoint.
     *
     * Strategies may need to generate callback URLs before the route collection
     * is fully materialized, so this accessor gives them a single source of
     * truth for the expected route name.
     */
    public function callbackName(): string
    {
        return Config::string('sso.routes.callback_name', 'sso.callback');
    }

    /**
     * Determine whether the SCIM API routes should be registered.
     *
     * Disabling SCIM here allows applications to ship interactive SSO support
     * without exposing the provisioning API surface.
     */
    public function scimEnabled(): bool
    {
        return Config::boolean('sso.routes.scim_enabled', true);
    }

    /**
     * Return the URI prefix for the SCIM API surface.
     *
     * Controllers and API clients assume this prefix aligns with the SCIM
     * version being exposed by the package.
     */
    public function scimPrefix(): string
    {
        return Config::string('sso.routes.scim_prefix', 'scim/v2');
    }

    /**
     * Return the route-name prefix used for the SCIM API surface.
     *
     * This namespacing keeps SCIM routes distinct from the interactive login
     * surface even when applications override both groups.
     */
    public function scimNamePrefix(): string
    {
        return Config::string('sso.routes.scim_name_prefix', 'sso.scim.');
    }

    /**
     * Return the middleware stack applied to SCIM routes.
     *
     * The default includes both API middleware and the package's SCIM auth
     * middleware so bearer-token validation and request shaping happen before
     * any SCIM controller executes.
     *
     * @return array<int, string>
     */
    public function scimMiddleware(): array
    {
        return array_values(array_map(
            static function (mixed $value): string {
                if (!is_string($value) || $value === '') {
                    throw InvalidScimRouteMiddlewareException::forValue();
                }

                return $value;
            },
            Config::array('sso.routes.scim_middleware', ['api', 'sso.scim']),
        ));
    }
}
