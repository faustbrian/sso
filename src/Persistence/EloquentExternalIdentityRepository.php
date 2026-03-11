<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Persistence;

use Cline\SSO\Configuration\Configuration;
use Cline\SSO\Contracts\ExternalIdentityRepositoryInterface;
use Cline\SSO\Data\ExternalIdentityRecord;
use Cline\SSO\Data\PrincipalReference;
use Cline\SSO\Models\ExternalIdentity;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

/**
 * Eloquent-backed repository for durable external identity links.
 *
 * This repository owns the storage-side rules for mapping a provider-issued
 * issuer and subject tuple to the local principal selected by the application.
 * Login, linking, and reconciliation flows depend on it to answer identity
 * resolution questions consistently without speaking Eloquent directly.
 *
 * The abstraction exists to separate write-model concerns from the rest of the
 * package. Consumers work with immutable records, while this repository handles
 * natural-key lookups, id generation, projection, and morph resolution for the
 * configured principal model behind the scenes.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class EloquentExternalIdentityRepository implements ExternalIdentityRepositoryInterface
{
    /**
     * Return the stored identity mapping for an exact provider, issuer, and
     * subject tuple.
     *
     * The lookup uses the same boundary that the package treats as the remote
     * identity natural key. A `null` result means the login flow is still in a
     * first-link or first-provision path for that remote principal.
     */
    public function find(string $providerId, string $issuer, string $subject): ?ExternalIdentityRecord
    {
        $identity = ExternalIdentity::query()
            ->where('sso_provider_id', $providerId)
            ->where('issuer', $issuer)
            ->where('subject', $subject)
            ->first();

        return $identity instanceof ExternalIdentity ? $this->toRecord($identity) : null;
    }

    /**
     * Return the stored mapping for a local principal within one provider and
     * issuer boundary.
     *
     * This lookup supports flows that start from the local account side, such
     * as relinking, unlinking, or detecting whether an application principal is
     * already attached to a provider before creating a second link.
     */
    public function findByLinkedPrincipal(
        string $providerId,
        string $issuer,
        PrincipalReference $principal,
    ): ?ExternalIdentityRecord {
        $identity = ExternalIdentity::query()
            ->where('sso_provider_id', $providerId)
            ->where('issuer', $issuer)
            ->where('user_id', $principal->key)
            ->first();

        return $identity instanceof ExternalIdentity ? $this->toRecord($identity) : null;
    }

    /**
     * Return every external identity known for a provider, optionally narrowed
     * to one issuer.
     *
     * Results are ordered by subject so operator-facing screens and audit flows
     * receive deterministic output regardless of database engine defaults.
     *
     * @return array<int, ExternalIdentityRecord>
     */
    public function allForProvider(string $providerId, ?string $issuer = null): array
    {
        $query = ExternalIdentity::query()
            ->where('sso_provider_id', $providerId)
            ->orderBy('subject');

        if ($issuer !== null) {
            $query->where('issuer', $issuer);
        }

        /** @var Collection<int, ExternalIdentity> $identities */
        $identities = $query->get();

        return $identities
            ->map(fn (ExternalIdentity $identity): ExternalIdentityRecord => $this->toRecord($identity))
            ->all();
    }

    /**
     * Upsert a provider-issued identity mapping and return the normalized
     * record that was persisted.
     *
     * The provider, issuer, and subject tuple is treated as the natural key.
     * When that tuple does not exist yet, the repository generates a package-
     * owned ULID for the row identifier. When it already exists, the row is
     * updated in place so repeated linking, reconciliation, and email snapshot
     * refreshes remain idempotent.
     *
     * Side effects:
     * - inserts a new link row on first association
     * - updates the linked principal and email snapshot on subsequent saves
     * - always returns a freshly projected immutable record
     */
    public function save(ExternalIdentityRecord $record): ExternalIdentityRecord
    {
        /** @var ExternalIdentity $identity */
        $identity = ExternalIdentity::query()->updateOrCreate([
            'sso_provider_id' => $record->providerId,
            'issuer' => $record->issuer,
            'subject' => $record->subject,
        ], [
            'id' => $record->id ?? (string) Str::ulid(),
            'user_id' => $record->linkedPrincipal->key,
            'email_snapshot' => $record->emailSnapshot,
        ]);

        return $this->toRecord($identity);
    }

    /**
     * Delete every mapping for the local principal inside one provider and
     * issuer scope.
     *
     * This is intentionally a silent no-op when nothing matches, which makes
     * unlink operations and reconciliation cleanup safe to retry without first
     * checking for existence.
     */
    public function deleteByLinkedPrincipal(
        string $providerId,
        string $issuer,
        PrincipalReference $principal,
    ): void {
        ExternalIdentity::query()
            ->where('sso_provider_id', $providerId)
            ->where('issuer', $issuer)
            ->where('user_id', $principal->key)
            ->delete();
    }

    /**
     * Project a mutable Eloquent model into the package's immutable record
     * shape.
     *
     * Projection happens eagerly so callers receive a stable snapshot even if
     * the underlying model is later mutated elsewhere in the request lifecycle.
     * It also normalizes the local principal into morph-reference form so
     * higher-level code does not need to understand the storage model.
     */
    private function toRecord(ExternalIdentity $identity): ExternalIdentityRecord
    {
        return new ExternalIdentityRecord(
            id: $identity->id,
            emailSnapshot: $identity->email_snapshot,
            issuer: $identity->issuer,
            linkedPrincipal: new PrincipalReference(
                type: $this->principalMorphClass(),
                key: (string) $identity->user_id,
            ),
            providerId: $identity->sso_provider_id,
            subject: $identity->subject,
        );
    }

    /**
     * Resolve the morph class of the configured principal model for principal
     * references.
     *
     * Principal references store morph types instead of raw class names so they
     * remain compatible with custom morph maps and other polymorphic Eloquent
     * setups used by the host application.
     */
    private function principalMorphClass(): string
    {
        /** @var class-string<Model> $modelClass */
        $modelClass = Configuration::principal()->model();
        $model = new $modelClass();

        return $model->getMorphClass();
    }
}
