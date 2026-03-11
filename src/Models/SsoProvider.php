<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Models;

use Carbon\CarbonInterface;
use Cline\SSO\Configuration\Configuration;
use Cline\VariableKeys\Database\Concerns\HasVariablePrimaryKey;
use Illuminate\Database\Eloquent\Attributes\Scope;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\SoftDeletes;
use Override;

use function collect;
use function in_array;
use function is_array;

/**
 * Eloquent model representing a configured SSO provider together with its
 * mutable operational state.
 *
 * The row combines administrator-managed configuration such as driver choice,
 * authority, credentials, issuer expectations, and SCIM settings with runtime
 * telemetry such as validation timestamps, metadata refresh outcomes, and last
 * usage markers. That makes the model the package's storage-level source of
 * truth for both how a provider should behave and how it has behaved recently.
 *
 * This type belongs to the default persistence layer, not the public package
 * API. Repositories project it into immutable records so orchestration code can
 * read provider state without depending on Eloquent mutation semantics,
 * encrypted attribute casting, or lazy-loaded relationships.
 *
 * Architectural notes:
 * - `scheme` is the stable public identifier used by login routes and UI
 * - `driver` selects the protocol strategy that interprets provider settings
 * - operational timestamps are intentionally persisted for operator visibility
 * - SCIM group helpers persist immediately because this model is the write-side
 *   authority for SCIM ownership state
 *
 * @author Brian Faust <brian@cline.sh>
 * @phpstan-type SsoProviderSettings array{
 *     email_attribute?: string,
 *     metadata_url?: string,
 *     name_id_format?: string,
 *     provision_mode?: string,
 *     require_signature?: bool,
 *     scim_managed_group_ids?: array<int, string>,
 *     scim_role_mapping?: array<string, string>,
 *     sign_authn_request?: bool,
 *     signature_algorithm?: string,
 *     x509_certificates?: array<int, string>
 * }
 * @property        string                            $authority
 * @property        string                            $client_id
 * @property        string                            $client_secret
 * @property        string                            $display_name
 * @property        string                            $driver
 * @property        bool                              $enabled
 * @property        bool                              $enforce_sso
 * @property        null|int                          $external_identities_count
 * @property        Collection<int, ExternalIdentity> $externalIdentities
 * @property        string                            $id
 * @property        bool                              $is_default
 * @property        null|string                       $last_failure_reason
 * @property        null|CarbonInterface              $last_login_failed_at
 * @property        null|CarbonInterface              $last_login_succeeded_at
 * @property        null|string                       $last_metadata_refresh_error
 * @property        null|CarbonInterface              $last_metadata_refresh_failed_at
 * @property        null|CarbonInterface              $last_metadata_refreshed_at
 * @property        null|CarbonInterface              $last_used_at
 * @property        null|CarbonInterface              $last_validated_at
 * @property        null|string                       $last_validation_error
 * @property        null|CarbonInterface              $last_validation_failed_at
 * @property        null|CarbonInterface              $last_validation_succeeded_at
 * @property        string                            $scheme
 * @property        bool                              $scim_enabled
 * @property        null|CarbonInterface              $scim_last_used_at
 * @property        null|string                       $scim_token_hash
 * @property        null|CarbonInterface              $secret_rotated_at
 * @property        null|array<string, mixed>         $settings
 * @property        string                            $tenant_id
 * @property        null|string                       $valid_issuer
 * @property        bool                              $validate_issuer
 * @method   static Builder<self>                     query()
 */
final class SsoProvider extends Model
{
    /** @use HasFactory<Factory<static>> */
    use HasFactory;
    use HasVariablePrimaryKey;
    use SoftDeletes;

    #[Override()]
    protected $fillable = [
        'id',
        'tenant_id',
        'driver',
        'scheme',
        'display_name',
        'authority',
        'client_id',
        'client_secret',
        'valid_issuer',
        'validate_issuer',
        'enabled',
        'is_default',
        'enforce_sso',
        'scim_enabled',
        'scim_token_hash',
        'scim_last_used_at',
        'last_used_at',
        'last_login_succeeded_at',
        'last_login_failed_at',
        'last_failure_reason',
        'last_metadata_refreshed_at',
        'last_metadata_refresh_failed_at',
        'last_metadata_refresh_error',
        'last_validated_at',
        'last_validation_succeeded_at',
        'last_validation_failed_at',
        'last_validation_error',
        'secret_rotated_at',
        'settings',
    ];

    /**
     * Return every external identity mapping issued under this provider.
     *
     * These rows are the durable login-resolution cache for the provider. Once
     * an account has been linked or provisioned, future sign-ins can consult
     * this relationship instead of repeating first-login discovery logic.
     *
     * @return HasMany<ExternalIdentity, $this>
     */
    public function externalIdentities(): HasMany
    {
        return $this->hasMany(ExternalIdentity::class, 'sso_provider_id');
    }

    /**
     * Return the configured owner that scopes this provider, when present.
     *
     * Ownership is resolved from package configuration so providers can be
     * attached to whatever tenant, account, or organization model the host
     * application uses. An empty owner key represents a global provider rather
     * than a broken relationship.
     *
     * @return BelongsTo<Model, $this>
     */
    public function owner(): BelongsTo
    {
        /** @var class-string<Model> $modelClass */
        $modelClass = Configuration::owner()->model();

        $ownerKey = Configuration::owner()->ownerKey();

        $column = Configuration::owner()->foreignKeyColumn();

        return $this->belongsTo($modelClass, $column, $ownerKey);
    }

    /**
     * Return the configured table name for provider storage.
     *
     * Table resolution stays dynamic so published configuration can relocate
     * package tables without forcing consumers to replace the model class.
     */
    #[Override()]
    public function getTable(): string
    {
        return Configuration::tables()->providers();
    }

    /**
     * Return the settings payload normalized to the provider-settings shape.
     *
     * Invalid, missing, or non-array payloads collapse to an empty array so
     * callers can consume optional provider settings without repeatedly
     * defending against malformed persisted state. This keeps the model's read
     * semantics aligned with the immutable {@see SsoProviderRecord} projection.
     *
     * @return SsoProviderSettings
     */
    public function settingsMap(): array
    {
        /** @var null|array<string, mixed> $settings */
        $settings = $this->settings;

        if (!is_array($settings)) {
            return [];
        }

        /** @var SsoProviderSettings $settings */
        return $settings;
    }

    /**
     * Return the SCIM group identifiers explicitly managed by this provider.
     *
     * Empty identifiers are filtered out and array keys are normalized so
     * downstream reconciliation code receives a clean, deterministic list of
     * actual ownership claims.
     *
     * @return array<int, string>
     */
    public function scimManagedGroupIds(): array
    {
        /** @var array<int, string> $groupIds */
        $groupIds = $this->settingsMap()['scim_managed_group_ids'] ?? [];

        return collect($groupIds)
            ->filter(static fn (string $groupId): bool => $groupId !== '')
            ->values()
            ->all();
    }

    /**
     * Determine whether the provider currently claims ownership of a SCIM
     * managed group identifier.
     *
     * This centralizes ownership checks around the normalized list returned by
     * {@see scimManagedGroupIds()} so callers do not accidentally diverge on
     * empty-value handling or comparison strictness.
     */
    public function managesScimGroup(string $groupId): bool
    {
        return in_array($groupId, $this->scimManagedGroupIds(), true);
    }

    /**
     * Add a SCIM-managed group identifier and persist the updated settings.
     *
     * The operation is intentionally write-through. Callers typically invoke it
     * from controller or adapter flows where the provider model is the canonical
     * owner of SCIM group state, so changes are saved immediately rather than
     * staged for a later flush.
     *
     * Duplicate identifiers are removed before persistence, which keeps the
     * method idempotent and safe to retry after partial failures.
     */
    public function addScimManagedGroup(string $groupId): void
    {
        $settings = $this->settingsMap();
        $settings['scim_managed_group_ids'] = collect($this->scimManagedGroupIds())
            ->push($groupId)
            ->unique()
            ->values()
            ->all();

        $this->forceFill([
            'settings' => $settings,
        ])->save();
    }

    /**
     * Remove a SCIM-managed group identifier and persist the updated settings.
     *
     * Missing identifiers are ignored, making the helper safe for cleanup and
     * rollback flows that may be replayed after partial reconciliation work.
     */
    public function removeScimManagedGroup(string $groupId): void
    {
        $settings = $this->settingsMap();
        $settings['scim_managed_group_ids'] = collect($this->scimManagedGroupIds())
            ->reject(static fn (string $managedGroupId): bool => $managedGroupId === $groupId)
            ->values()
            ->all();

        $this->forceFill([
            'settings' => $settings,
        ])->save();
    }

    /**
     * Scope queries to providers that are currently enabled.
     *
     * This keeps the package's most common operational filter reusable at the
     * model layer for ad hoc queries, even though repository code may choose to
     * apply equivalent constraints explicitly for clearer search semantics.
     *
     * @param  Builder<self> $query
     * @return Builder<self>
     */
    #[Scope()]
    protected function enabled(Builder $query): Builder
    {
        return $query->where('enabled', true);
    }

    /**
     * Return the cast map used to normalize provider attributes at runtime.
     *
     * The cast map defines several package-level invariants:
     * - secrets stay encrypted at rest
     * - boolean feature toggles read consistently across database drivers
     * - operational telemetry fields hydrate as datetimes for jobs and UIs
     * - settings hydrate as arrays so helper methods can safely normalize them
     *
     * @return array<string, string>
     */
    #[Override()]
    protected function casts(): array
    {
        return [
            'client_secret' => 'encrypted',
            'enabled' => 'boolean',
            'enforce_sso' => 'boolean',
            'is_default' => 'boolean',
            'scim_enabled' => 'boolean',
            'validate_issuer' => 'boolean',
            'settings' => 'array',
            'scim_last_used_at' => 'datetime',
            'last_used_at' => 'datetime',
            'last_login_succeeded_at' => 'datetime',
            'last_login_failed_at' => 'datetime',
            'last_metadata_refreshed_at' => 'datetime',
            'last_metadata_refresh_failed_at' => 'datetime',
            'last_validated_at' => 'datetime',
            'last_validation_succeeded_at' => 'datetime',
            'last_validation_failed_at' => 'datetime',
            'secret_rotated_at' => 'datetime',
        ];
    }
}
