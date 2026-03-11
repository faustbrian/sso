<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Support;

use Cline\SSO\Contracts\ScimGroupAdapterInterface;
use Cline\SSO\Data\SsoProviderRecord;

/**
 * Stub SCIM group adapter used when the host application has no group sync.
 *
 * Returning inert values keeps the package bootable and makes it explicit that
 * SCIM group support is an application extension point rather than a built-in
 * persistence concern of the package itself.
 *
 * This is intentionally a null object rather than an exception-throwing stub,
 * which keeps optional SCIM surfaces safe to register before an application has
 * implemented real group behavior.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class NullScimGroupAdapter implements ScimGroupAdapterInterface
{
    /**
     * Report no SCIM-manageable groups for the provider.
     *
     * @return array<int, array<string, mixed>>
     */
    public function list(SsoProviderRecord $provider): array
    {
        return [];
    }

    /**
     * Echo the creation payload without persisting a remote group.
     *
     * This keeps controller responses structurally valid while making the lack
     * of persistence obvious to integrators.
     *
     * @param array<string, mixed> $payload
     *
     * @return array<string, mixed>
     */
    public function create(SsoProviderRecord $provider, array $payload): array
    {
        return $payload;
    }

    /**
     * Indicate that the group identifier cannot be resolved.
     *
     * @return null|array<string, mixed>
     */
    public function find(SsoProviderRecord $provider, string $groupId): ?array
    {
        return null;
    }

    /**
     * Echo the patch payload without mutating any backing store.
     *
     * The null adapter is fail-open with respect to response structure but
     * performs no durable side effects.
     *
     * @param array<string, mixed> $payload
     *
     * @return array<string, mixed>
     */
    public function patch(SsoProviderRecord $provider, string $groupId, array $payload): array
    {
        return $payload;
    }

    /**
     * Intentionally discard delete requests when no adapter is configured.
     */
    public function delete(SsoProviderRecord $provider, string $groupId): void {}
}
