<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Fixtures;

use Cline\SSO\Contracts\ScimGroupAdapterInterface;
use Cline\SSO\Data\SsoProviderRecord;

use function array_values;
use function mb_strtolower;
use function str_replace;

/**
 * @author Brian Faust <brian@cline.sh>
 */
final class TestScimGroupAdapter implements ScimGroupAdapterInterface
{
    /** @var array<string, array<string, mixed>> */
    public static array $groups = [];

    public function list(SsoProviderRecord $provider): array
    {
        return array_values(self::$groups);
    }

    public function create(SsoProviderRecord $provider, array $payload): array
    {
        $resource = [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:Group'],
            'id' => mb_strtolower(str_replace(' ', '-', (string) $payload['displayName'])),
            'displayName' => $payload['displayName'],
            'members' => $payload['members'] ?? [],
            'meta' => ['resourceType' => 'Group'],
        ];

        self::$groups[$resource['id']] = $resource;

        return $resource;
    }

    public function find(SsoProviderRecord $provider, string $groupId): ?array
    {
        return self::$groups[$groupId] ?? null;
    }

    public function patch(SsoProviderRecord $provider, string $groupId, array $payload): array
    {
        $resource = self::$groups[$groupId] ?? [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:Group'],
            'id' => $groupId,
            'displayName' => $groupId,
            'members' => [],
            'meta' => ['resourceType' => 'Group'],
        ];

        self::$groups[$groupId] = $resource;

        return $resource;
    }

    public function delete(SsoProviderRecord $provider, string $groupId): void
    {
        unset(self::$groups[$groupId]);
    }
}
