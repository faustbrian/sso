<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Persistence;

use Cline\SSO\Configuration\Configuration;
use Cline\SSO\Contracts\ProviderRepositoryInterface;
use Cline\SSO\Data\OwnerReference;
use Cline\SSO\Data\ProviderSearchCriteria;
use Cline\SSO\Data\SsoProviderRecord;
use Cline\SSO\Enums\BooleanFilter;
use Cline\SSO\Models\SsoProvider;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;

use function is_numeric;

/**
 * Eloquent-backed repository for persisted SSO provider configuration.
 *
 * This repository is the read and write policy boundary for provider storage.
 * It centralizes query shaping, ordering, owner scoping, lifecycle mutations,
 * and model-to-record projection so the rest of the package never needs to
 * depend on Eloquent-specific details.
 *
 * The abstraction exists because provider state is richer than a simple model
 * fetch. Search criteria, enabled-state filtering, SCIM token lookup, owner
 * interpretation, and external identity counts all need to be presented in a
 * stable immutable form to controllers, commands, and orchestration services.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class EloquentProviderRepository implements ProviderRepositoryInterface
{
    /**
     * Return providers ordered for operator-facing selection and management.
     *
     * Resolution order is part of the repository contract:
     * - criteria filters are applied first
     * - owner mismatches short-circuit to an empty result
     * - default providers sort ahead of non-default providers
     * - display names provide stable secondary ordering
     *
     * That ordering keeps interactive login screens and administrative UIs
     * deterministic across requests and database engines.
     *
     * @return array<int, SsoProviderRecord>
     */
    public function all(ProviderSearchCriteria $criteria): array
    {
        /** @var Builder<SsoProvider> $query */
        $query = SsoProvider::query()->withCount('externalIdentities');

        if ($criteria->enabled !== BooleanFilter::Any) {
            $query->where('enabled', $criteria->enabled->toBool());
        }

        if ($criteria->enforceSso !== BooleanFilter::Any) {
            $query->where('enforce_sso', $criteria->enforceSso->toBool());
        }

        if ($criteria->scimEnabled !== BooleanFilter::Any) {
            $query->where('scim_enabled', $criteria->scimEnabled->toBool());
        }

        if ($criteria->schemes !== []) {
            $query->whereIn('scheme', $criteria->schemes);
        }

        if ($criteria->owner instanceof OwnerReference) {
            if ($criteria->owner->type !== $this->ownerMorphClass()) {
                return [];
            }

            $query->where('tenant_id', $criteria->owner->key);
        }

        /** @var Collection<int, SsoProvider> $providers */
        $providers = $query
            ->orderByDesc('is_default')
            ->orderBy('display_name')
            ->get();

        return $providers
            ->map(fn (SsoProvider $provider): SsoProviderRecord => $this->toRecord($provider))
            ->all();
    }

    /**
     * Return the current persisted state for a provider identifier.
     *
     * The returned record is enriched with external identity counts so callers
     * do not need to issue a second query for common operator-facing details.
     */
    public function findById(string $providerId): ?SsoProviderRecord
    {
        $provider = SsoProvider::query()->withCount('externalIdentities')->find($providerId);

        return $provider instanceof SsoProvider ? $this->toRecord($provider) : null;
    }

    /**
     * Return the enabled SCIM provider that owns a hashed bearer token.
     *
     * Resolution deliberately fails closed unless all of the following are
     * true: the provider exists, SCIM is enabled, the token hash matches, and
     * the provider itself is enabled. That keeps SCIM middleware from having to
     * duplicate package policy about which providers may authenticate API
     * traffic.
     */
    public function findByScimTokenHash(string $tokenHash): ?SsoProviderRecord
    {
        $provider = SsoProvider::query()
            ->withCount('externalIdentities')
            ->where('scim_enabled', true)
            ->where('scim_token_hash', $tokenHash)
            ->where('enabled', true)
            ->first();

        return $provider instanceof SsoProvider ? $this->toRecord($provider) : null;
    }

    /**
     * Return a provider by scheme, optionally requiring it to be enabled.
     *
     * Schemes act as the public-facing identifiers used by interactive login
     * routes and administrative workflows, so this lookup is the bridge between
     * route input and stored provider configuration.
     */
    public function findByScheme(string $scheme, bool $enabledOnly = false): ?SsoProviderRecord
    {
        /** @var Builder<SsoProvider> $query */
        $query = SsoProvider::query()->withCount('externalIdentities')->where('scheme', $scheme);

        if ($enabledOnly) {
            $query->where('enabled', true);
        }

        $provider = $query->first();

        return $provider instanceof SsoProvider ? $this->toRecord($provider) : null;
    }

    /**
     * Persist a new provider model and return its projected read model.
     *
     * Creation happens through the write model, then the new row is reloaded
     * with relationship counts so callers immediately receive the same immutable
     * shape used everywhere else in the package.
     *
     * @param array<string, mixed> $attributes
     */
    public function create(array $attributes): SsoProviderRecord
    {
        /** @var SsoProvider $provider */
        $provider = SsoProvider::query()->create($attributes);

        return $this->toRecord($provider->loadCount('externalIdentities'));
    }

    /**
     * Apply attribute updates to an existing provider and return the refreshed
     * projection.
     *
     * Returning `null` signals that the provider no longer exists. When the row
     * is present, attributes are force-filled and saved immediately so the
     * repository remains the authoritative write path for provider state.
     *
     * @param array<string, mixed> $attributes
     */
    public function update(string $providerId, array $attributes): ?SsoProviderRecord
    {
        $provider = SsoProvider::query()->find($providerId);

        if (!$provider instanceof SsoProvider) {
            return null;
        }

        $provider->forceFill($attributes)->save();

        return $this->toRecord($provider->loadCount('externalIdentities'));
    }

    /**
     * Soft-delete a provider when it exists.
     *
     * The boolean return value lets callers distinguish between a missing
     * provider and a successfully issued delete without inspecting Eloquent's
     * internals. Soft deletion preserves historical linkage data for audits and
     * operator review.
     */
    public function delete(string $providerId): bool
    {
        $provider = SsoProvider::query()->find($providerId);

        if (!$provider instanceof SsoProvider) {
            return false;
        }

        return (bool) $provider->delete();
    }

    /**
     * Project a mutable Eloquent model into the package's immutable read model.
     *
     * The projection deliberately snapshots owner references, timestamps,
     * relationship counts, and settings payload so callers are insulated from
     * later model mutation or lazy-loading side effects.
     */
    private function toRecord(SsoProvider $provider): SsoProviderRecord
    {
        $externalIdentityCount = $provider->external_identities_count;

        return new SsoProviderRecord(
            id: $provider->id,
            driver: $provider->driver,
            scheme: $provider->scheme,
            displayName: $provider->display_name,
            authority: $provider->authority,
            clientId: $provider->client_id,
            clientSecret: $provider->client_secret,
            validIssuer: $provider->valid_issuer,
            validateIssuer: $provider->validate_issuer,
            enabled: $provider->enabled,
            isDefault: $provider->is_default,
            enforceSso: $provider->enforce_sso,
            scimEnabled: $provider->scim_enabled,
            scimTokenHash: $provider->scim_token_hash,
            scimLastUsedAt: $provider->scim_last_used_at,
            lastUsedAt: $provider->last_used_at,
            lastLoginSucceededAt: $provider->last_login_succeeded_at,
            lastLoginFailedAt: $provider->last_login_failed_at,
            lastFailureReason: $provider->last_failure_reason,
            lastMetadataRefreshedAt: $provider->last_metadata_refreshed_at,
            lastMetadataRefreshFailedAt: $provider->last_metadata_refresh_failed_at,
            lastMetadataRefreshError: $provider->last_metadata_refresh_error,
            lastValidatedAt: $provider->last_validated_at,
            lastValidationSucceededAt: $provider->last_validation_succeeded_at,
            lastValidationFailedAt: $provider->last_validation_failed_at,
            lastValidationError: $provider->last_validation_error,
            secretRotatedAt: $provider->secret_rotated_at,
            owner: $this->ownerReference($provider),
            settings: $provider->settings,
            externalIdentityCount: is_numeric($externalIdentityCount) ? (int) $externalIdentityCount : 0,
        );
    }

    /**
     * Convert a stored owner foreign key into the package's owner reference.
     *
     * Empty owner identifiers are treated as an unscoped provider rather than
     * an invalid owner reference. This matches the package's semantics for
     * globally available providers that are not owned by a tenant record.
     */
    private function ownerReference(SsoProvider $provider): ?OwnerReference
    {
        if ($provider->tenant_id === '') {
            return null;
        }

        return new OwnerReference($this->ownerMorphClass(), (string) $provider->tenant_id);
    }

    /**
     * Resolve the configured owner model's morph class for filter alignment.
     *
     * Repository criteria and persisted owner references must agree on morph
     * representation or owner-scoped queries would drift from stored data. The
     * repository therefore resolves the morph class from configuration once at
     * the boundary where search criteria are interpreted.
     */
    private function ownerMorphClass(): string
    {
        /** @var class-string<Model> $modelClass */
        $modelClass = Configuration::owner()->model();
        $model = new $modelClass();

        return $model->getMorphClass();
    }
}
