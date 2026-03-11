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
 * Translates local user storage into SCIM user resource documents.
 *
 * The SCIM controllers rely on this contract for list, create, and mutation
 * operations so the package can expose a standards-based API without imposing
 * a specific user persistence model on the host application. Implementations
 * are responsible for mapping between local user semantics and SCIM resource
 * semantics while honoring the constraints of the supplied provider record.
 *
 * Adapter methods should return payloads that are already normalized into
 * SCIM-compatible arrays so controllers can focus on protocol concerns such as
 * status codes, envelopes, and pagination.
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface ScimUserAdapterInterface
{
    /**
     * List users visible to the provider, optionally applying a SCIM filter.
     *
     * Implementations are responsible for interpreting the filter string, if
     * supported, and returning only the resources visible within the provider's
     * scope.
     *
     * @return array<int, array<string, mixed>>
     */
    public function list(SsoProviderRecord $provider, ?string $filter = null): array;

    /**
     * Create a new SCIM user from the inbound request payload.
     *
     * Implementations should validate and persist the payload according to the
     * application's user model, then return the created resource in SCIM
     * response format.
     *
     * @param  array<string, mixed> $payload
     * @return array<string, mixed>
     */
    public function create(SsoProviderRecord $provider, array $payload): array;

    /**
     * Retrieve a single SCIM user by its stable adapter identifier.
     *
     * Returning `null` signals that the resource does not exist or is outside
     * the provider's visible scope.
     *
     * @return null|array<string, mixed>
     */
    public function find(SsoProviderRecord $provider, string $userId): ?array;

    /**
     * Replace a SCIM user with a full resource representation.
     *
     * Implementations should treat the payload as a full replacement document
     * and return the post-write user representation.
     *
     * @param  array<string, mixed> $payload
     * @return array<string, mixed>
     */
    public function replace(SsoProviderRecord $provider, string $userId, array $payload): array;

    /**
     * Apply a SCIM PATCH document to an existing user and return the result.
     *
     * Implementations should apply supported SCIM patch operations to the
     * targeted user and return the resulting resource representation.
     *
     * @param  array<string, mixed> $payload
     * @return array<string, mixed>
     */
    public function patch(SsoProviderRecord $provider, string $userId, array $payload): array;
}
