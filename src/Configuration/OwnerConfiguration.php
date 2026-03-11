<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Configuration;

use Illuminate\Support\Facades\Config;

/**
 * Reads owner-model integration settings for provider ownership.
 *
 * Provider records may be global or scoped to an owning account boundary
 * depending on the host application. These accessors define how the package
 * should reference that owner model in relationships, repository queries, and
 * schema assumptions so ownership behavior stays consistent across models,
 * jobs, and authentication flows.
 *
 * The reader also owns the fallback rule for owner key types. If the
 * application does not define an owner-specific identifier strategy, the
 * package reuses the global auth primary key type so owner and principal
 * foreign keys remain structurally compatible by default.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class OwnerConfiguration
{
    /**
     * Return the application model class that represents a provider owner.
     *
     * Providers may be globally available or partitioned by an owning tenant,
     * workspace, or account model. This value tells the package which local
     * model anchors that ownership boundary when relationships and lookups are
     * built.
     */
    public function model(): string
    {
        return Config::string('sso.models.owner', 'App\\Models\\Owner');
    }

    /**
     * Return the foreign-key column stored on provider records for owners.
     *
     * Repository queries and model relationships both depend on this column
     * name matching the package's persisted schema. It describes the package
     * side of the relationship, not the key name on the owner model itself.
     */
    public function foreignKeyColumn(): string
    {
        return Config::string('sso.foreign_keys.owner.column', 'tenant_id');
    }

    /**
     * Return the owner model column that package foreign keys reference.
     *
     * Together with {@see foreignKeyColumn()}, this determines how provider
     * ownership is joined back to the application model. Custom owner keys are
     * especially important when the host application uses UUIDs or another
     * non-default identifier column.
     */
    public function ownerKey(): string
    {
        return Config::string('sso.foreign_keys.owner.owner_key', 'id');
    }

    /**
     * Return the owner-key type used for casts, schema, and morph metadata.
     *
     * Resolution order is owner-specific configuration first, then the package
     * falls back to {@see Configuration::auth()->primaryKeyType()} so owner
     * foreign keys inherit the package-wide identifier strategy by default.
     */
    public function keyType(): string
    {
        return Config::string('sso.foreign_keys.owner.type', Configuration::auth()->primaryKeyType());
    }
}
