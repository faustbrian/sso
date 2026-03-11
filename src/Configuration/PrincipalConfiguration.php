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
 * Reads principal-model integration settings for local identity resolution.
 *
 * External identities ultimately map back to an application-owned principal
 * model. This reader defines the model class and foreign-key conventions the
 * package should use when persisting that relationship, so login
 * reconciliation and SCIM flows can work against strongly typed settings
 * instead of raw config keys.
 *
 * The reader also owns the fallback rule for principal key types. When the
 * application does not provide a principal-specific identifier strategy, the
 * package reuses the primary authentication key configuration so all
 * principal-facing foreign keys remain structurally compatible.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class PrincipalConfiguration
{
    /**
     * Return the application model class that represents a local principal.
     *
     * This is the model the package authenticates into after a successful SSO
     * exchange. Repositories, link records, and resolver implementations all
     * rely on this class string to describe the local account boundary.
     */
    public function model(): string
    {
        return Config::string('sso.models.principal', 'App\\Models\\Principal');
    }

    /**
     * Return the foreign-key column stored on identity records for principals.
     *
     * The package persists this column on external identity records so later
     * sign-ins can resolve the same local principal without re-running
     * application-specific heuristics.
     */
    public function foreignKeyColumn(): string
    {
        return Config::string('sso.foreign_keys.principal.column', 'user_id');
    }

    /**
     * Return the principal model column that package foreign keys reference.
     *
     * This identifies the application-side key that linked identities should
     * target. It intentionally stays separate from {@see foreignKeyColumn()} so
     * the package can support custom primary keys and non-standard owner keys.
     */
    public function ownerKey(): string
    {
        return Config::string('sso.foreign_keys.principal.owner_key', 'id');
    }

    /**
     * Return the principal-key type used for casts, schema, and relation
     * lookups.
     *
     * Resolution order is principal-specific configuration first, then the
     * package inherits the global authentication primary-key strategy. That
     * keeps identity records structurally compatible with the application's
     * chosen account identifier format by default.
     */
    public function keyType(): string
    {
        return Config::string('sso.foreign_keys.principal.type', Configuration::auth()->primaryKeyType());
    }
}
