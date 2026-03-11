<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Contracts;

use Cline\SSO\Data\SsoProviderRecord;
use Cline\SSO\ValueObjects\ResolvedIdentity;
use Illuminate\Http\Request;

/**
 * Driver contract for provider-specific SSO protocols such as OIDC and SAML.
 *
 * Strategies encapsulate protocol details while the rest of the package works
 * with provider records and resolved identities. This keeps the manager,
 * controllers, and jobs protocol-agnostic while still allowing each driver to
 * implement the validation, redirect, token, and metadata semantics required
 * by its protocol family.
 *
 * Implementations are expected to treat the supplied provider record as the
 * authoritative source of persisted configuration and to throw when required
 * protocol invariants cannot be satisfied. Callers depend on that fail-fast
 * behavior to surface configuration problems clearly.
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface SsoStrategy
{
    /**
     * Build the external authorization URL that starts the login handshake.
     *
     * The generated URL should embed any protocol-specific state required to
     * bind the eventual callback to the originating browser session.
     */
    public function buildAuthorizationUrl(SsoProviderRecord $provider, Request $request, string $state, string $nonce): string;

    /**
     * Resolve the authenticated identity from the provider callback request.
     *
     * Implementations should return only normalized, trusted identities. Any
     * signature, issuer, audience, or replay validation failures should be
     * surfaced as exceptions rather than partially populated identities.
     */
    public function resolveIdentity(SsoProviderRecord $provider, Request $request, string $nonce): ResolvedIdentity;

    /**
     * Validate the provider configuration and return field-level failures.
     *
     * This method is used by administrative tooling and metadata refresh flows
     * to determine whether a stored provider record is complete enough to run a
     * live authentication exchange.
     *
     * @return array<string, null|scalar>
     */
    public function validateConfiguration(SsoProviderRecord $provider): array;

    /**
     * Import authoritative metadata from the remote provider.
     *
     * Implementations may return normalized settings, authority hints, and a
     * verified issuer value that callers persist onto the provider record.
     * Returned values should be safe to store directly after package-level
     * normalization.
     *
     * @return array{authority?: null|string, settings?: array<string, mixed>, valid_issuer?: null|string}
     */
    public function importConfiguration(SsoProviderRecord $provider): array;

    /**
     * Refresh previously imported metadata and return validation-style errors.
     *
     * Implementations should invalidate any protocol-specific caches needed to
     * force a fresh view of remote metadata before re-running validation.
     *
     * @return array<string, null|scalar>
     */
    public function refreshMetadata(SsoProviderRecord $provider): array;
}
