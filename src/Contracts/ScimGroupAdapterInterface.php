<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Contracts;

use Cline\SSO\Data\SsoProviderRecord;

/**
 * Translates local group storage into SCIM group resource documents.
 *
 * Controllers depend on this contract to remain storage-agnostic while still
 * exposing a SCIM-compliant surface. Implementations are responsible for
 * validating provider-specific capabilities, mapping local group identifiers to
 * SCIM resource identifiers, and returning payloads that can be serialized
 * directly into SCIM responses. The abstraction exists because group data
 * frequently lives in application-specific models or external systems, while
 * the package needs one consistent contract for SCIM routes regardless of how
 * those groups are stored.
 *
 * Adapter methods are expected to operate within the constraints of the
 * supplied provider record, which may enable or disable group features or
 * encode owner-specific behavior. Controllers assume adapters enforce those
 * invariants and surface unsupported operations through exceptions rather than
 * leaking partial or malformed SCIM payloads.
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface ScimGroupAdapterInterface
{
    /**
     * List all groups exposed by the provider's SCIM integration.
     *
     * The returned payloads should already be normalized into SCIM resource
     * shapes so controllers can wrap them without further translation.
     * Implementations should return only resources visible within the supplied
     * provider scope and omit local-only metadata that has no SCIM meaning.
     *
     * @return array<int, array<string, mixed>>
     */
    public function list(SsoProviderRecord $provider): array;

    /**
     * Create a new SCIM group from the inbound request payload.
     *
     * Implementations should validate and persist the payload according to
     * local storage rules, then return the newly created resource in SCIM
     * response format. Any generated identifiers should be stable enough for
     * later `find`, `patch`, and `delete` calls to address the same resource.
     *
     * @param  array<string, mixed> $payload
     * @return array<string, mixed>
     */
    public function create(SsoProviderRecord $provider, array $payload): array;

    /**
     * Retrieve a single SCIM group by its stable adapter identifier.
     *
     * Returning `null` signals that the requested resource does not exist or is
     * not visible within the provider's current scope. Implementations should
     * reserve exceptions for transportable SCIM errors such as unsupported
     * operations or invalid payload semantics, not ordinary "missing resource"
     * outcomes.
     *
     * @return null|array<string, mixed>
     */
    public function find(SsoProviderRecord $provider, string $groupId): ?array;

    /**
     * Apply a SCIM PATCH document to an existing group and return the result.
     *
     * Implementations should apply the SCIM patch semantics supported by the
     * local group store and return the post-mutation resource representation.
     * Partial update ordering matters here: callers expect the returned
     * document to represent the persisted state after every accepted operation
     * has been applied.
     *
     * @param  array<string, mixed> $payload
     * @return array<string, mixed>
     */
    public function patch(SsoProviderRecord $provider, string $groupId, array $payload): array;

    /**
     * Delete the referenced group or throw if the adapter cannot fulfill it.
     *
     * Implementations should use exceptions to report unsupported operations or
     * invalid identifiers so controllers can translate them into SCIM errors.
     * A successful return indicates the backing store accepted the deletion and
     * there is no response body to serialize.
     */
    public function delete(SsoProviderRecord $provider, string $groupId): void;
}
