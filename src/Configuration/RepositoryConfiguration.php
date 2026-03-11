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
 * Resolves repository implementations used by the manager, jobs, and
 * controllers.
 *
 * The package defaults to Eloquent-backed repositories, but applications may
 * replace those persistence adapters to integrate with an alternate storage
 * layer or a customized domain model. This reader keeps those substitutions in
 * one place so the service provider can bind repositories without hard-coding
 * implementation classes.
 *
 * Returning class strings here also preserves a clean separation between
 * configuration discovery and container lifecycle management.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class RepositoryConfiguration
{
    /**
     * Return the repository class responsible for provider records.
     *
     * This repository owns queries and writes around provider definitions,
     * metadata refreshes, and provider lookups during authentication. The
     * returned class string is later bound by the service provider, so this
     * method controls which persistence adapter backs provider management
     * without coupling callers to a concrete storage mechanism.
     */
    public function provider(): string
    {
        return Config::string('sso.repositories.provider');
    }

    /**
     * Return the repository class responsible for external identities.
     *
     * This repository owns subject-to-principal mappings and is consulted during
     * login reconciliation and SCIM synchronization flows. Swapping this class
     * lets applications preserve the package contract while adapting to a
     * different schema, storage backend, or domain model around account links.
     */
    public function externalIdentity(): string
    {
        return Config::string('sso.repositories.external_identity');
    }
}
