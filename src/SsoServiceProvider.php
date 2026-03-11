<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO;

use Cline\Morphism\Concerns\ConfiguresMorphism;
use Cline\SSO\Configuration\Configuration;
use Cline\SSO\Console\Commands\ReconcileScimIdentitiesCommand;
use Cline\SSO\Console\Commands\RecoverSsoAccessCommand;
use Cline\SSO\Console\Commands\RefreshSsoProviderMetadataCommand;
use Cline\SSO\Contracts\AuditSinkInterface;
use Cline\SSO\Contracts\ExternalIdentityRepositoryInterface;
use Cline\SSO\Contracts\PrincipalResolverInterface;
use Cline\SSO\Contracts\ProviderRepositoryInterface;
use Cline\SSO\Contracts\ScimGroupAdapterInterface;
use Cline\SSO\Contracts\ScimReconcilerInterface;
use Cline\SSO\Contracts\ScimUserAdapterInterface;
use Cline\SSO\Contracts\SsoStrategy;
use Cline\SSO\Drivers\SsoStrategyResolver;
use Cline\SSO\Exceptions\InvalidAuditSinkException;
use Cline\SSO\Exceptions\InvalidConfiguredContractException;
use Cline\SSO\Exceptions\InvalidExternalIdentityRepositoryException;
use Cline\SSO\Exceptions\InvalidPrincipalResolverException;
use Cline\SSO\Exceptions\InvalidProviderRepositoryException;
use Cline\SSO\Exceptions\InvalidScimGroupAdapterException;
use Cline\SSO\Exceptions\InvalidScimReconcilerException;
use Cline\SSO\Exceptions\InvalidScimUserAdapterException;
use Cline\SSO\Exceptions\UnsupportedConfiguredDriverException;
use Cline\SSO\Http\Middleware\AuthenticateScimRequest;
use Cline\SSO\Models\ExternalIdentity;
use Cline\SSO\Models\SsoProvider;
use Cline\VariableKeys\Enums\PrimaryKeyType;
use Cline\VariableKeys\Facades\VariableKeys;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Routing\Router;
use Override;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

/**
 * Package service provider that composes the SSO package into a host Laravel
 * application.
 *
 * This provider is the package's composition root. It validates configured
 * extension points, registers orchestration services, exposes routes and
 * commands, aligns morph aliases and primary-key generation, and resolves
 * protocol strategies before application traffic reaches controllers, jobs, or
 * middleware.
 *
 * The provider is intentionally strict during registration and boot. Incorrect
 * contract bindings, empty class configuration, or unsupported driver
 * strategies fail early so broken SSO behavior does not surface later during a
 * login attempt, SCIM request, or metadata refresh job.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class SsoServiceProvider extends PackageServiceProvider
{
    use ConfiguresMorphism;

    /**
     * Declare the package assets, migrations, views, and maintenance commands.
     *
     * This is the static package manifest consumed by Laravel Package Tools
     * before any runtime bindings are resolved.
     */
    public function configurePackage(Package $package): void
    {
        $package
            ->name('sso')
            ->hasConfigFile()
            ->hasMigrations(['create_sso_tables'])
            ->hasViews()
            ->hasCommands([
                RefreshSsoProviderMetadataCommand::class,
                ReconcileScimIdentitiesCommand::class,
                RecoverSsoAccessCommand::class,
            ]);
    }

    /**
     * Register the package's core bindings and container-backed extension
     * points.
     *
     * Registration order matters conceptually even though Laravel defers
     * singleton instantiation:
     * - application extension points are registered first
     * - the strategy resolver is then built from configured drivers
     * - the public SSO manager is registered last as the orchestration facade
     */
    #[Override()]
    public function registeringPackage(): void
    {
        $this->app->singleton(
            PrincipalResolverInterface::class,
            fn (Application $app): PrincipalResolverInterface => $this->resolvePrincipalResolver($app),
        );
        $this->app->singleton(
            AuditSinkInterface::class,
            fn (Application $app): AuditSinkInterface => $this->resolveAuditSink($app),
        );
        $this->app->singleton(
            ProviderRepositoryInterface::class,
            fn (Application $app): ProviderRepositoryInterface => $this->resolveProviderRepository($app),
        );
        $this->app->singleton(
            ExternalIdentityRepositoryInterface::class,
            fn (Application $app): ExternalIdentityRepositoryInterface => $this->resolveExternalIdentityRepository($app),
        );
        $this->app->singleton(
            ScimUserAdapterInterface::class,
            fn (Application $app): ScimUserAdapterInterface => $this->resolveScimUserAdapter($app),
        );
        $this->app->singleton(
            ScimGroupAdapterInterface::class,
            fn (Application $app): ScimGroupAdapterInterface => $this->resolveScimGroupAdapter($app),
        );
        $this->app->singleton(
            ScimReconcilerInterface::class,
            fn (Application $app): ScimReconcilerInterface => $this->resolveScimReconciler($app),
        );
        $this->app->singleton(SsoStrategyResolver::class, fn (Application $app): SsoStrategyResolver => new SsoStrategyResolver(
            $this->resolveStrategies($app),
        ));
        $this->app->singleton(SsoManager::class);
    }

    /**
     * Finish boot-time setup that depends on registered bindings and config.
     *
     * These steps run after singleton registration so routing, morph aliases,
     * and variable key configuration can assume package bindings already exist.
     * The order is deliberate: translations first, then key and morph setup,
     * then routes, then middleware aliases that reference those routes.
     */
    #[Override()]
    public function bootingPackage(): void
    {
        $this->loadTranslationsFrom(__DIR__.'/../lang', 'sso');
        $this->registerVariableKeys();
        $this->configureMorphism('sso');
        $this->registerMorphAliases();
        $this->registerRoutes();
        $this->registerMiddleware();
    }

    /**
     * Register package model aliases for polymorphic relations and activity logs.
     *
     * The package uses a stable `sso_provider` alias when recording activity and
     * other polymorphic references. Registering the alias here keeps consumers
     * from having to duplicate package model knowledge in their own morph-map
     * bootstrap code.
     */
    private function registerMorphAliases(): void
    {
        Relation::morphMap([
            'sso_provider' => SsoProvider::class,
        ]);
    }

    /**
     * Register web and SCIM routes according to the package route toggles.
     *
     * Resolution order is explicit: interactive web routes may be loaded
     * independently of SCIM routes, while SCIM routes short-circuit entirely
     * when the dedicated toggle is disabled.
     */
    private function registerRoutes(): void
    {
        if (Configuration::routes()->enabled()) {
            $this->loadRoutesFrom(__DIR__.'/../routes/web.php');
        }

        if (!Configuration::routes()->scimEnabled()) {
            return;
        }

        $this->loadRoutesFrom(__DIR__.'/../routes/scim.php');
    }

    /**
     * Alias the SCIM authentication middleware for route declarations.
     *
     * Registering the alias here keeps route files decoupled from the concrete
     * middleware class name and mirrors how host applications typically consume
     * package middleware.
     */
    private function registerMiddleware(): void
    {
        $this->app->make(Router::class)
            ->aliasMiddleware('sso.scim', AuthenticateScimRequest::class);
    }

    /**
     * Configure variable primary-key generation for package-owned models.
     *
     * Both provider and external identity models must share the same primary
     * key policy so package migrations, factories, and repositories all agree
     * on identifier format across IDs, UUIDs, or ULIDs.
     */
    private function registerVariableKeys(): void
    {
        $primaryKeyType = PrimaryKeyType::tryFrom(Configuration::auth()->primaryKeyType()) ?? PrimaryKeyType::ID;

        VariableKeys::map([
            SsoProvider::class => [
                'primary_key_type' => $primaryKeyType,
            ],
            ExternalIdentity::class => [
                'primary_key_type' => $primaryKeyType,
            ],
        ]);
    }

    /**
     * Read a configured implementation class name for a package extension
     * point.
     *
     * This method centralizes the mapping between config keys and concrete
     * extension points. Empty strings are rejected so resolution fails fast
     * during boot instead of much later when an HTTP request or queue job first
     * touches the binding.
     */
    private function configuredContract(string $key): string
    {
        $value = match ($key) {
            'sso.contracts.principal_resolver' => Configuration::contracts()->principalResolver(),
            'sso.contracts.audit_sink' => Configuration::contracts()->auditSink(),
            'sso.repositories.provider' => Configuration::repositories()->provider(),
            'sso.repositories.external_identity' => Configuration::repositories()->externalIdentity(),
            'sso.contracts.scim_user_adapter' => Configuration::contracts()->scimUserAdapter(),
            'sso.contracts.scim_group_adapter' => Configuration::contracts()->scimGroupAdapter(),
            'sso.contracts.scim_reconciler' => Configuration::contracts()->scimReconciler(),
            default => throw InvalidConfiguredContractException::forKey($key),
        };

        if ($value === '') {
            throw InvalidConfiguredContractException::forKey($key);
        }

        return $value;
    }

    /**
     * Resolve and type-check the configured principal resolver implementation.
     *
     * The resolver defines how remote identities map onto local principals, so
     * the provider refuses to continue if the configured service does not honor
     * the package contract exactly.
     */
    private function resolvePrincipalResolver(Application $app): PrincipalResolverInterface
    {
        $resolver = $app->make($this->configuredContract('sso.contracts.principal_resolver'));

        if (!$resolver instanceof PrincipalResolverInterface) {
            throw InvalidPrincipalResolverException::create();
        }

        return $resolver;
    }

    /**
     * Resolve and type-check the configured audit sink implementation.
     *
     * Audit capture is optional from the application's perspective, but once a
     * class is configured it must satisfy the package contract to keep security
     * event recording predictable.
     */
    private function resolveAuditSink(Application $app): AuditSinkInterface
    {
        $sink = $app->make($this->configuredContract('sso.contracts.audit_sink'));

        if (!$sink instanceof AuditSinkInterface) {
            throw InvalidAuditSinkException::create();
        }

        return $sink;
    }

    /**
     * Resolve and type-check the configured provider repository implementation.
     *
     * Repository replacement is an intentional extension point, but the
     * returned service must still preserve the package's provider persistence
     * contract.
     */
    private function resolveProviderRepository(Application $app): ProviderRepositoryInterface
    {
        $repository = $app->make($this->configuredContract('sso.repositories.provider'));

        if (!$repository instanceof ProviderRepositoryInterface) {
            throw InvalidProviderRepositoryException::create();
        }

        return $repository;
    }

    /**
     * Resolve and type-check the configured external-identity repository.
     *
     * The package relies on consistent link lookup and upsert semantics, so the
     * provider guards this replacement point aggressively at boot.
     */
    private function resolveExternalIdentityRepository(Application $app): ExternalIdentityRepositoryInterface
    {
        $repository = $app->make($this->configuredContract('sso.repositories.external_identity'));

        if (!$repository instanceof ExternalIdentityRepositoryInterface) {
            throw InvalidExternalIdentityRepositoryException::create();
        }

        return $repository;
    }

    /**
     * Resolve and type-check the configured SCIM user adapter implementation.
     *
     * SCIM user reconciliation depends on this adapter for write-side user
     * behavior, so contract mismatches are treated as boot-time configuration
     * errors rather than deferred runtime failures.
     */
    private function resolveScimUserAdapter(Application $app): ScimUserAdapterInterface
    {
        $adapter = $app->make($this->configuredContract('sso.contracts.scim_user_adapter'));

        if (!$adapter instanceof ScimUserAdapterInterface) {
            throw InvalidScimUserAdapterException::create();
        }

        return $adapter;
    }

    /**
     * Resolve and type-check the configured SCIM group adapter implementation.
     *
     * Group reconciliation must remain interchangeable without sacrificing type
     * safety, which is why the provider validates the adapter eagerly.
     */
    private function resolveScimGroupAdapter(Application $app): ScimGroupAdapterInterface
    {
        $adapter = $app->make($this->configuredContract('sso.contracts.scim_group_adapter'));

        if (!$adapter instanceof ScimGroupAdapterInterface) {
            throw InvalidScimGroupAdapterException::create();
        }

        return $adapter;
    }

    /**
     * Resolve and type-check the configured SCIM reconciliation service.
     *
     * This is the top-level SCIM orchestration hook, so the provider ensures it
     * satisfies the contract before any reconciliation command or API request
     * can resolve it.
     */
    private function resolveScimReconciler(Application $app): ScimReconcilerInterface
    {
        $reconciler = $app->make($this->configuredContract('sso.contracts.scim_reconciler'));

        if (!$reconciler instanceof ScimReconcilerInterface) {
            throw InvalidScimReconcilerException::create();
        }

        return $reconciler;
    }

    /**
     * Resolve every configured protocol strategy keyed by provider driver name.
     *
     * Resolution order follows the configured driver map. Each strategy class
     * must resolve from the container and implement the shared protocol
     * contract before the resolver is exposed, which guarantees that later
     * manager calls can select strategies by driver name without additional
     * runtime type checks.
     *
     * @return array<string, SsoStrategy>
     */
    private function resolveStrategies(Application $app): array
    {
        $strategies = [];

        foreach (Configuration::drivers()->all() as $driver => $strategyClass) {
            $strategy = $app->make($strategyClass);

            if (!$strategy instanceof SsoStrategy) {
                throw UnsupportedConfiguredDriverException::forDriver($driver);
            }

            $strategies[$driver] = $strategy;
        }

        return $strategies;
    }
}
