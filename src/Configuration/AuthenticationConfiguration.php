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
 * Reads authentication settings that sit at the boundary between package
 * identities and Laravel's auth system.
 *
 * These values are consumed by login controllers, recovery flows, and model
 * persistence code whenever the package needs to translate a successful SSO
 * assertion into a local authenticated session or package-owned database
 * record. Centralizing them here gives the rest of the package a single source
 * of truth for guard selection and key-shape assumptions.
 *
 * The defaults are intentionally conservative: browser logins target Laravel's
 * standard `web` guard and package-owned records assume integer-style primary
 * keys until the host application opts into UUID or ULID semantics.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class AuthenticationConfiguration
{
    /**
     * Return the Laravel guard that should receive successful SSO logins.
     *
     * Controllers and account-recovery commands both defer to this value so the
     * package signs users into the same authentication stack the host
     * application expects for interactive sessions. Keeping the lookup here
     * avoids hidden divergence between browser callbacks, manual recovery
     * tooling, and any future entry points that complete the login lifecycle.
     *
     * The method always returns a non-empty string because `Config::string()`
     * normalizes the configured value or falls back to `web` when the package
     * configuration is absent. That fallback order matters because the package
     * treats the guard as the final handoff point from validated external
     * identity data into Laravel's session-based authentication layer.
     */
    public function guard(): string
    {
        return Config::string('sso.guard', 'web');
    }

    /**
     * Return the configured primary key strategy for package-owned records.
     *
     * This value is reused by owner and principal configuration readers when
     * they need a default key strategy. That shared fallback keeps
     * package-owned foreign keys structurally aligned with the application's
     * identifier format unless a more specific owner- or principal-level
     * override is supplied.
     *
     * Downstream consumers rely on this method to answer the "shape" of stored
     * identifiers rather than the exact database column name, so callers can
     * use it when choosing casts, schema definitions, and runtime validation.
     * Resolution order is package-global first, then owner/principal specific
     * readers may override it when they need a narrower rule.
     */
    public function primaryKeyType(): string
    {
        return Config::string('sso.primary_key_type', 'id');
    }
}
