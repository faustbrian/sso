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
 * Provides the database table names used by the package models.
 *
 * Migrations, Eloquent models, and repository queries all depend on these
 * names staying aligned. Centralizing table-name resolution here allows the
 * package to support schema customization without scattering raw config lookups
 * throughout the persistence layer.
 *
 * These accessors intentionally expose only the package-owned tables. They are
 * part of the contract between configuration, model metadata, and repository
 * implementations.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class TableConfiguration
{
    /**
     * Return the table that stores provider definitions and driver settings.
     *
     * Provider records carry the persisted driver name, ownership scope, and
     * remote metadata references required to start an authentication flow. This
     * name must remain aligned with migrations and model metadata because the
     * package resolves providers dynamically during both browser and API-driven
     * entry points.
     */
    public function providers(): string
    {
        return Config::string('sso.table_names.providers', 'sso_providers');
    }

    /**
     * Return the table that stores provider-issued subject mappings.
     *
     * These records link upstream provider subjects to local principal
     * identifiers and are therefore critical to idempotent login
     * reconciliation. Repository implementations depend on this table being
     * stable enough to enforce the effective uniqueness of provider, issuer,
     * and subject tuples.
     */
    public function externalIdentities(): string
    {
        return Config::string('sso.table_names.external_identities', 'external_identities');
    }
}
