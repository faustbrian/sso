<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Data;

/**
 * Identifies a local principal by type and stable key.
 *
 * The package stores principal references on linked identities so it can later
 * resolve the same local identity even when the host application uses custom
 * models or non-integer primary keys. This keeps the external-identity
 * repository decoupled from any concrete Authenticatable implementation.
 *
 * The reference is intentionally minimal: enough information to relocate the
 * principal later without embedding a full model snapshot into package
 * records. That keeps external-identity links resilient to ordinary attribute
 * changes on the user model while still giving resolver implementations the
 * information they need to rehydrate the principal on subsequent logins.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class PrincipalReference
{
    /**
     * @param string $type Application model class or discriminator used to
     *                     resolve the principal later; this is part of the
     *                     durable lookup contract stored with external identity
     *                     links
     * @param string $key  Stable local identifier for the principal within the
     *                     resolved type
     */
    public function __construct(
        public string $type,
        public string $key,
    ) {}
}
