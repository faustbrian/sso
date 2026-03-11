<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Data;

/**
 * Identifies the local boundary that owns a provider definition.
 *
 * Owner references are carried through repository queries and provider records
 * so administrative, recovery, and lookup workflows can target the correct
 * account boundary even when applications use custom models or key formats.
 * This allows the package to support organization-, workspace-, or
 * account-owned providers without coupling itself to a specific tenancy model.
 *
 * The reference carries only the information needed to identify the owner
 * boundary. Repository implementations remain responsible for deciding how
 * that boundary maps to the underlying storage model, while higher-level
 * package services can still express owner-aware filtering and auditing in a
 * backend-neutral way.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class OwnerReference
{
    /**
     * @param string $type Application model class or discriminator for the owner boundary;
     *                     this must remain stable across reads so repository
     *                     filters can match persisted provider ownership
     * @param string $key  Stable identifier for the owner instance within the
     *                     application's tenancy model
     */
    public function __construct(
        public string $type,
        public string $key,
    ) {}
}
