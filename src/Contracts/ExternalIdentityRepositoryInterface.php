<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Contracts;

use Cline\SSO\Data\ExternalIdentityRecord;
use Cline\SSO\Data\PrincipalReference;

/**
 * Persists the mapping between remote subjects and local application
 * principals.
 *
 * This repository sits on the critical path between a resolved SSO identity
 * and subsequent sign-ins. It owns the durable link from a provider-qualified
 * subject to a local principal reference so repeated logins can be resolved
 * idempotently without re-running application-specific linking logic.
 *
 * Implementations must preserve issuer, subject, and provider uniqueness so
 * the same remote account always resolves consistently. They should also treat
 * linked-principal lookups as a first-class use case because unlinking and
 * administrative reconciliation frequently work from the local side outward.
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface ExternalIdentityRepositoryInterface
{
    /**
     * Find a previously linked external identity by its provider-qualified key.
     *
     * This is the primary lookup used during login callbacks once the upstream
     * issuer and subject have been extracted from the validated identity
     * assertion. Returning `null` means no durable link exists yet, so callers
     * may continue to fallback heuristics such as email matching or automatic
     * provisioning.
     */
    public function find(string $providerId, string $issuer, string $subject): ?ExternalIdentityRecord;

    /**
     * Find a linked identity by the local principal it resolves to.
     *
     * This supports unlinking, reconciliation, and administrative tooling that
     * starts from the application principal rather than the remote identity.
     * Implementations should apply the same uniqueness guarantees here as they
     * do for remote-subject lookups so link maintenance remains deterministic.
     */
    public function findByLinkedPrincipal(
        string $providerId,
        string $issuer,
        PrincipalReference $principal,
    ): ?ExternalIdentityRecord;

    /**
     * List stored identities for a provider, optionally constrained by issuer.
     *
     * Bulk operations such as provider cleanup and reconciliation use this view
     * of the repository to iterate over all linked identities belonging to the
     * same provider. Passing `null` for the issuer must widen the search to all
     * issuers associated with the provider rather than silently filtering to an
     * empty set.
     *
     * @return array<int, ExternalIdentityRecord>
     */
    public function allForProvider(string $providerId, ?string $issuer = null): array;

    /**
     * Create or update an external identity mapping and return its stored state.
     *
     * Implementations should preserve idempotency for repeated saves of the
     * same provider, issuer, and subject tuple. Callers rely on the returned
     * record reflecting the final persisted state after any insert-or-update
     * logic completes. Side effects should be limited to persistence of the
     * link itself; higher-level login or audit behavior belongs in callers.
     */
    public function save(ExternalIdentityRecord $record): ExternalIdentityRecord;

    /**
     * Delete a linked identity by the local principal it points at.
     *
     * This is the inverse of {@see findByLinkedPrincipal()} and is typically
     * used when an application account is unlinked from a provider-issued
     * subject. Implementations should make the operation safe to call when no
     * matching link exists so administrative unlink flows remain idempotent.
     */
    public function deleteByLinkedPrincipal(
        string $providerId,
        string $issuer,
        PrincipalReference $principal,
    ): void;
}
