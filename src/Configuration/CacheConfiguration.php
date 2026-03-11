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
 * Centralizes cache policy for remote identity-provider metadata.
 *
 * SSO drivers depend on third-party discovery documents, signing keys, and
 * imported metadata that are expensive to fetch repeatedly and may be served
 * by rate-limited infrastructure. This reader keeps those TTL decisions in one
 * place so the runtime can trade network cost against freshness consistently
 * across drivers, jobs, and administrative refresh flows.
 *
 * Each accessor exposes a different stability boundary. Discovery documents and
 * imported metadata can usually tolerate moderately stale values, while JWK
 * material often needs a shorter refresh window so key rotations are observed
 * before token verification starts to fail.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class CacheConfiguration
{
    /**
     * Return the cache lifetime for OIDC discovery documents, in seconds.
     *
     * Discovery endpoints change infrequently, but stale issuer metadata can
     * break login bootstrapping or callback validation. The default therefore
     * favors a short, production-safe cache window that reduces network traffic
     * without making administrators wait long for endpoint changes to propagate.
     */
    public function discoveryTtl(): int
    {
        return Config::integer('sso.cache.discovery_ttl', 600);
    }

    /**
     * Return the cache lifetime for remote JSON Web Key Sets, in seconds.
     *
     * Token verification depends on current signing keys, and upstream IdPs may
     * rotate those keys independently of any other metadata change. A dedicated
     * TTL lets the package refresh key material more aggressively than other
     * cached documents so signature validation does not get stuck on retired
     * keys.
     */
    public function jwksTtl(): int
    {
        return Config::integer('sso.cache.jwks_ttl', 600);
    }

    /**
     * Return the cache lifetime for imported provider metadata, in seconds.
     *
     * Imported metadata powers provider validation, background refresh jobs,
     * and administrative troubleshooting. This TTL therefore governs how often
     * the package re-queries upstream providers for changes to certificates,
     * endpoints, or supported capabilities before serving the cached snapshot
     * again.
     */
    public function metadataTtl(): int
    {
        return Config::integer('sso.cache.metadata_ttl', 3_600);
    }
}
