<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Fixtures;

use Cline\SSO\Contracts\ScimUserAdapterInterface;
use Cline\SSO\Data\SsoProviderRecord;

use function array_values;

/**
 * @author Brian Faust <brian@cline.sh>
 */
final class TestScimUserAdapter implements ScimUserAdapterInterface
{
    /** @var array<string, array<string, mixed>> */
    public static array $users = [];

    public function list(SsoProviderRecord $provider, ?string $filter = null): array
    {
        return array_values(self::$users);
    }

    public function create(SsoProviderRecord $provider, array $payload): array
    {
        $resource = [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'id' => $payload['externalId'] ?? 'user-1',
            'externalId' => $payload['externalId'] ?? null,
            'userName' => $payload['userName'],
            'active' => $payload['active'] ?? true,
            'meta' => ['resourceType' => 'User'],
        ];

        self::$users[$resource['id']] = $resource;

        return $resource;
    }

    public function find(SsoProviderRecord $provider, string $userId): ?array
    {
        return self::$users[$userId] ?? null;
    }

    public function replace(SsoProviderRecord $provider, string $userId, array $payload): array
    {
        return self::$users[$userId] = [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'id' => $userId,
            'externalId' => $payload['externalId'] ?? null,
            'userName' => $payload['userName'],
            'active' => $payload['active'] ?? true,
            'meta' => ['resourceType' => 'User'],
        ];
    }

    public function patch(SsoProviderRecord $provider, string $userId, array $payload): array
    {
        $resource = self::$users[$userId] ?? [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'id' => $userId,
            'meta' => ['resourceType' => 'User'],
        ];

        foreach ((array) ($payload['Operations'] ?? []) as $operation) {
            if (!(($operation['path'] ?? null) === 'active')) {
                continue;
            }

            $resource['active'] = (bool) ($operation['value'] ?? false);
        }

        self::$users[$userId] = $resource;

        return $resource;
    }
}
