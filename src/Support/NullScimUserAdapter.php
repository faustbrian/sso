<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Support;

use Cline\SSO\Contracts\ScimUserAdapterInterface;
use Cline\SSO\Data\SsoProviderRecord;

/**
 * Stub SCIM user adapter that keeps the package operational without sync logic.
 *
 * This adapter is useful as the default binding because it makes the package's
 * SCIM endpoints and jobs safe to boot even when the host application has not
 * implemented user provisioning yet.
 *
 * Like the other null implementations, it preserves protocol shape while doing
 * no durable work, which makes incomplete integrations obvious but not fatal.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class NullScimUserAdapter implements ScimUserAdapterInterface
{
    /**
     * Report no remotely managed users for the provider.
     *
     * @return array<int, array<string, mixed>>
     */
    public function list(SsoProviderRecord $provider, ?string $filter = null): array
    {
        return [];
    }

    /**
     * Echo the validated payload so controller responses remain well-formed.
     *
     * No local account is created; the returned payload is only a structural
     * placeholder.
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
     * Indicate that no user can be resolved by identifier.
     *
     * @return null|array<string, mixed>
     */
    public function find(SsoProviderRecord $provider, string $userId): ?array
    {
        return null;
    }

    /**
     * Echo the replacement payload without persisting any change.
     *
     * @param array<string, mixed> $payload
     *
     * @return array<string, mixed>
     */
    public function replace(SsoProviderRecord $provider, string $userId, array $payload): array
    {
        return $payload;
    }

    /**
     * Echo the patch payload without applying any mutation.
     *
     * @param array<string, mixed> $payload
     *
     * @return array<string, mixed>
     */
    public function patch(SsoProviderRecord $provider, string $userId, array $payload): array
    {
        return $payload;
    }
}
