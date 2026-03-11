<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Contracts;

use Cline\SSO\Data\ProviderSearchCriteria;
use Cline\SSO\Data\SsoProviderRecord;

/**
 * Provides persistence operations for configured SSO providers.
 *
 * The manager, HTTP controllers, jobs, and maintenance commands all delegate
 * to this abstraction so package orchestration code does not depend on a
 * specific storage engine. It is the authoritative persistence boundary for
 * provider definitions, enablement state, SCIM tokens, and imported metadata.
 *
 * Implementations are expected to enforce package invariants such as unique
 * schemes, stable provider identifiers, and predictable filtering semantics for
 * search criteria. Higher-level services assume those guarantees when they
 * build login and provisioning workflows. That makes this contract more than a
 * generic CRUD surface: it is the place where package-level persistence rules
 * are normalized so interactive login, SCIM authentication, and background
 * maintenance operate against the same provider view.
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface ProviderRepositoryInterface
{
    /**
     * Return every provider matching the supplied search criteria.
     *
     * Criteria combine operational filters such as enabled state, SCIM support,
     * owner scope, and scheme selection for both interactive UI and
     * maintenance workflows. Implementations should apply every populated
     * criterion deterministically so commands and controllers see the same
     * provider set. Returning records in a stable order is strongly preferred
     * so administrative lists and automation produce predictable output across
     * storage backends.
     *
     * @return array<int, SsoProviderRecord>
     */
    public function all(ProviderSearchCriteria $criteria): array;

    /**
     * Find a provider by its primary identifier.
     *
     * This is the canonical lookup used once another layer has already chosen a
     * provider record and needs to reload its current persisted state. The
     * returned record should reflect any persisted operational mutations such as
     * login timestamps, validation failures, token rotation, or metadata
     * refresh results.
     */
    public function findById(string $providerId): ?SsoProviderRecord;

    /**
     * Find the provider that owns the given hashed SCIM bearer token.
     *
     * SCIM authentication middleware uses this lookup after hashing the
     * presented bearer token so raw token material never needs to be persisted.
     * Implementations should treat the hash as a unique credential mapping and
     * must not perform partial or fuzzy matching.
     */
    public function findByScimTokenHash(string $tokenHash): ?SsoProviderRecord;

    /**
     * Find a provider by its human-facing scheme, optionally requiring
     * enablement.
     *
     * Interactive login flows use schemes as stable external identifiers, while
     * the optional enablement flag lets callers exclude disabled providers at
     * the persistence boundary. Implementations should preserve the invariant
     * that one public scheme resolves to at most one provider so route-based
     * login and callback handling remain unambiguous.
     */
    public function findByScheme(string $scheme, bool $enabledOnly = false): ?SsoProviderRecord;

    /**
     * Create a new provider record from normalized package attributes.
     *
     * Callers are expected to pass normalized package attributes rather than
     * raw request payloads so the repository can focus on persistence concerns.
     * Implementations should assign any storage-level defaults, persist the
     * record atomically, and return the freshly persisted projection that future
     * package layers will use for login and SCIM orchestration.
     *
     * @param array<string, mixed> $attributes
     */
    public function create(array $attributes): SsoProviderRecord;

    /**
     * Update an existing provider and return its current persisted state.
     *
     * Implementations should apply partial updates without discarding
     * previously stored fields that are not present in the attribute array.
     * Callers rely on this when recording operational side effects such as last
     * login timestamps or validation errors, where a write should mutate only a
     * narrow set of columns and leave the rest of the provider configuration
     * intact.
     *
     * @param array<string, mixed> $attributes
     */
    public function update(string $providerId, array $attributes): ?SsoProviderRecord;

    /**
     * Delete a provider and report whether a record was actually removed.
     *
     * Returning a boolean lets callers distinguish between successful deletion
     * and a no-op against a missing provider without having to perform a
     * separate existence check first. Any cascading cleanup policy for related
     * records, such as external-identity links, belongs to the implementation
     * and should leave the package in a consistent post-delete state.
     */
    public function delete(string $providerId): bool;
}
