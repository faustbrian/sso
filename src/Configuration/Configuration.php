<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Configuration;

/**
 * Entry point for strongly typed reads of the package configuration tree.
 *
 * Rather than scattering raw `config()` calls across controllers, jobs,
 * drivers, and repositories, the package routes configuration access through a
 * small set of focused reader objects. That keeps key names, fallback rules,
 * and normalization logic consistent while making each dependency explicit at
 * the call site.
 *
 * This class is intentionally stateless. Each method returns a fresh reader
 * instance so consumers can resolve only the configuration slice they need
 * without coupling unrelated subsystems together through a monolithic config
 * service. The class therefore acts as a composition root for configuration
 * readers rather than a cache or stateful registry.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class Configuration
{
    /**
     * Return authentication settings that govern login guards and identifier
     * strategies.
     *
     * This reader sits on the critical path for converting external identities
     * into local sessions and persisted package records. Consumers should treat
     * it as the package-level default source for auth boundary behavior before
     * applying owner- or principal-specific overrides.
     */
    public static function auth(): AuthenticationConfiguration
    {
        return new AuthenticationConfiguration();
    }

    /**
     * Return cache policy settings for remote provider metadata.
     *
     * Drivers and refresh jobs use this reader to decide how aggressively they
     * can reuse upstream metadata before performing another network request.
     * Keeping it isolated avoids leaking remote-cache assumptions into login,
     * persistence, or routing concerns.
     */
    public static function cache(): CacheConfiguration
    {
        return new CacheConfiguration();
    }

    /**
     * Return driver bindings for provider-specific strategy resolution.
     *
     * The strategy resolver depends on this mapping to turn persisted provider
     * driver names into concrete runtime implementations. This isolates the
     * persisted storage format from the container bindings used at runtime.
     */
    public static function drivers(): DriverConfiguration
    {
        return new DriverConfiguration();
    }

    /**
     * Return post-login redirect settings for interactive browser flows.
     *
     * Browser callback controllers use these values after a successful SSO
     * exchange has been translated into a local authenticated session. The
     * separation here keeps redirect policy independent from the mechanics of
     * identity resolution and guard selection.
     */
    public static function login(): LoginConfiguration
    {
        return new LoginConfiguration();
    }

    /**
     * Return route toggles and naming conventions for web and SCIM endpoints.
     *
     * The service provider consults this reader while deciding which HTTP
     * surfaces to register and how to namespace them. That makes route
     * registration deterministic and keeps enablement rules close to the route
     * metadata they influence.
     */
    public static function routes(): RouteConfiguration
    {
        return new RouteConfiguration();
    }

    /**
     * Return database table names used by the package models and repositories.
     *
     * Model metadata and persistence queries both depend on these names staying
     * aligned when an application customizes its schema layout. This reader is
     * therefore part of the contract between migrations, Eloquent models, and
     * repository implementations.
     */
    public static function tables(): TableConfiguration
    {
        return new TableConfiguration();
    }

    /**
     * Return owner model and foreign-key mapping rules for provider ownership.
     *
     * Provider ownership and owner-scoped lookups use this reader to stay
     * compatible with the host application's account-boundary model. It also
     * encapsulates the fallback sequence for owner identifier types.
     */
    public static function owner(): OwnerConfiguration
    {
        return new OwnerConfiguration();
    }

    /**
     * Return principal model and foreign-key mapping rules for local accounts.
     *
     * Identity reconciliation and repository writes use these settings to map
     * external subjects back to local application principals. It is the
     * canonical source for principal-key shape assumptions outside the auth
     * reader itself.
     */
    public static function principal(): PrincipalConfiguration
    {
        return new PrincipalConfiguration();
    }

    /**
     * Return concrete repository classes resolved by the service provider.
     *
     * Service-provider bindings consult this reader before wiring the package's
     * persistence layer into the container. That separation lets applications
     * replace persistence adapters without changing the manager or command
     * layers that consume the contracts.
     */
    public static function repositories(): RepositoryConfiguration
    {
        return new RepositoryConfiguration();
    }

    /**
     * Return application-extensible contract bindings for adapters and services.
     *
     * This reader groups the package's major extension points so the service
     * provider can validate and register them in a predictable way. It exists
     * to keep container wiring declarative instead of scattering
     * application-specific class names across the package.
     */
    public static function contracts(): ContractConfiguration
    {
        return new ContractConfiguration();
    }
}
