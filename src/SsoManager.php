<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO;

use Cline\SSO\Contracts\ExternalIdentityRepositoryInterface;
use Cline\SSO\Contracts\ProviderRepositoryInterface;
use Cline\SSO\Data\ExternalIdentityRecord;
use Cline\SSO\Data\PrincipalReference;
use Cline\SSO\Data\ProviderSearchCriteria;
use Cline\SSO\Data\SsoProviderRecord;
use Cline\SSO\Drivers\SsoStrategyResolver;
use Cline\SSO\Enums\BooleanFilter;

/**
 * High-level orchestration facade for provider storage and protocol strategy
 * operations.
 *
 * Controllers, middleware, jobs, and commands depend on this manager instead
 * of reaching into repositories or driver strategies directly. That keeps the
 * package's application-facing surface centered on immutable records and a
 * small set of explicit workflows even though storage and protocol mechanics
 * vary underneath.
 *
 * The manager is intentionally thin, but not incidental. It exists to define
 * the package's public coordination boundary:
 * - provider CRUD is routed through repository abstractions
 * - external identity linking is normalized around immutable records
 * - protocol-specific validation and metadata import are delegated by driver
 *
 * Because the class is readonly, its collaborators are fixed for the lifetime
 * of the container binding, reinforcing its role as a stable orchestration
 * surface rather than a mutable workflow object.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class SsoManager
{
    /**
     * @param ProviderRepositoryInterface         $providers          Persistence boundary for provider records
     * @param ExternalIdentityRepositoryInterface $externalIdentities Persistence boundary for linked identities
     * @param SsoStrategyResolver                 $resolver           Protocol strategy lookup for provider drivers
     */
    public function __construct(
        private ProviderRepositoryInterface $providers,
        private ExternalIdentityRepositoryInterface $externalIdentities,
        private SsoStrategyResolver $resolver,
    ) {}

    /**
     * Return interactive-login providers that are currently enabled.
     *
     * This is the manager's opinionated default listing path for end-user
     * surfaces. It bakes in the package rule that disabled providers should not
     * appear as selectable login options.
     *
     * @return array<int, SsoProviderRecord>
     */
    public function providers(): array
    {
        return $this->providers->all(
            new ProviderSearchCriteria(enabled: BooleanFilter::True),
        );
    }

    /**
     * Query providers using explicit administrative search criteria.
     *
     * This method preserves repository-defined filtering and ordering semantics
     * while giving higher-level callers one stable entry point for advanced
     * provider searches.
     *
     * @return array<int, SsoProviderRecord>
     */
    public function searchProviders(ProviderSearchCriteria $criteria): array
    {
        return $this->providers->all($criteria);
    }

    /**
     * Return the provider identified by its primary key, if it still exists.
     *
     * This is the canonical reload path for controllers, commands, and jobs
     * that only hold a stored provider identifier between execution steps.
     */
    public function findProviderById(string $providerId): ?SsoProviderRecord
    {
        return $this->providers->findById($providerId);
    }

    /**
     * Find a provider by its public login scheme, with optional enablement
     * enforcement.
     *
     * Interactive login routes depend on schemes as stable external
     * identifiers, so this method is the manager-level bridge from route input
     * to stored provider configuration.
     */
    public function findProviderByScheme(string $scheme, bool $enabledOnly = false): ?SsoProviderRecord
    {
        return $this->providers->findByScheme($scheme, $enabledOnly);
    }

    /**
     * Resolve the SCIM provider that owns the supplied hashed bearer token.
     *
     * SCIM middleware uses this instead of the repository directly so token
     * resolution remains part of the manager's public orchestration surface and
     * can keep the repository's fail-closed lookup semantics.
     */
    public function findProviderByScimTokenHash(string $tokenHash): ?SsoProviderRecord
    {
        return $this->providers->findByScimTokenHash($tokenHash);
    }

    /**
     * Persist a newly configured provider and return its normalized state.
     *
     * The returned record reflects the persisted provider after repository-side
     * projection, not merely the raw input attributes.
     *
     * @param array<string, mixed> $attributes
     */
    public function createProvider(array $attributes): SsoProviderRecord
    {
        return $this->providers->create($attributes);
    }

    /**
     * Update a provider in storage and return its refreshed projection.
     *
     * A `null` return indicates the provider could not be found at update time,
     * which allows callers to treat missing providers distinctly from successful
     * writes.
     *
     * @param array<string, mixed> $attributes
     */
    public function updateProvider(string $providerId, array $attributes): ?SsoProviderRecord
    {
        return $this->providers->update($providerId, $attributes);
    }

    /**
     * Soft-delete a provider by identifier.
     *
     * The boolean result mirrors the repository contract: `false` means the
     * provider was missing, while `true` means a delete operation was accepted.
     */
    public function deleteProvider(string $providerId): bool
    {
        return $this->providers->delete($providerId);
    }

    /**
     * Find an external identity link by provider-local issuer and subject.
     *
     * This is the canonical lookup used after a remote identity has been
     * resolved from the protocol driver and needs to be mapped to a local
     * account.
     */
    public function findExternalIdentity(string $providerId, string $issuer, string $subject): ?ExternalIdentityRecord
    {
        return $this->externalIdentities->find($providerId, $issuer, $subject);
    }

    /**
     * Persist a normalized external identity link for future login resolution.
     *
     * Login orchestration uses this after a principal has been approved for
     * linking or provisioning. The manager deliberately accepts the immutable
     * record shape so callers cannot depend on the underlying persistence model.
     */
    public function saveExternalIdentity(ExternalIdentityRecord $record): ExternalIdentityRecord
    {
        return $this->externalIdentities->save($record);
    }

    /**
     * Find an external identity through the local principal reference.
     *
     * This supports local-account-first workflows such as unlinking, conflict
     * detection, or administrative inspections of an already linked account.
     */
    public function findExternalIdentityByLinkedPrincipal(
        string $providerId,
        string $issuer,
        PrincipalReference $principal,
    ): ?ExternalIdentityRecord {
        return $this->externalIdentities->findByLinkedPrincipal($providerId, $issuer, $principal);
    }

    /**
     * Return every external identity known for a provider, optionally narrowed
     * to one issuer.
     *
     * This method exposes repository ordering and projection semantics through
     * the manager without leaking repository-specific implementation details.
     *
     * @return array<int, ExternalIdentityRecord>
     */
    public function externalIdentitiesForProvider(string $providerId, ?string $issuer = null): array
    {
        return $this->externalIdentities->allForProvider($providerId, $issuer);
    }

    /**
     * Delete linked identities by their local principal reference.
     *
     * This is useful for unlinking and cleanup flows that start from the local
     * account side of the relationship. Missing links remain a silent no-op via
     * the repository contract.
     */
    public function deleteExternalIdentityByLinkedPrincipal(
        string $providerId,
        string $issuer,
        PrincipalReference $principal,
    ): void {
        $this->externalIdentities->deleteByLinkedPrincipal($providerId, $issuer, $principal);
    }

    /**
     * Ask the configured driver to validate a provider's remote configuration.
     *
     * Strategy resolution happens by the provider's configured driver. The
     * manager does not interpret the returned payload; it simply preserves the
     * driver-specific diagnostics contract for callers that surface validation
     * results to operators.
     *
     * @return array<string, null|scalar>
     */
    public function validate(SsoProviderRecord $provider): array
    {
        return $this->resolver->resolve($provider)->validateConfiguration($provider);
    }

    /**
     * Import canonical metadata and provider-specific settings from the driver.
     *
     * Resolution order mirrors validation: the provider's driver selects the
     * strategy, and the strategy defines which attributes can be imported back
     * into persisted provider state.
     *
     * @return array{authority?: null|string, settings?: array<string, mixed>, valid_issuer?: null|string}
     */
    public function import(SsoProviderRecord $provider): array
    {
        return $this->resolver->resolve($provider)->importConfiguration($provider);
    }

    /**
     * Refresh cached provider metadata through the owning protocol strategy.
     *
     * This is a side-effecting protocol operation even though the manager
     * itself only returns the strategy payload. Callers are expected to decide
     * how and when refreshed metadata is persisted or surfaced.
     *
     * @return array<string, null|scalar>
     */
    public function refreshMetadata(SsoProviderRecord $provider): array
    {
        return $this->resolver->resolve($provider)->refreshMetadata($provider);
    }
}
