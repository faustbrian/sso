<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Models\SsoProvider;
use Tests\Fixtures\TestAuditSink;
use Tests\Fixtures\TestScimGroupAdapter;

it('shows patches deletes and rejects missing scim groups', function (): void {
    createScimGroupControllerProvider();

    TestScimGroupAdapter::$groups['engineers'] = [
        'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:Group'],
        'id' => 'engineers',
        'displayName' => 'Engineers',
        'members' => [],
        'meta' => ['resourceType' => 'Group'],
    ];

    $this->withHeader('Authorization', 'Bearer shipit-scim-token')
        ->getJson('/scim/v2/Groups/engineers')
        ->assertSuccessful()
        ->assertJsonPath('displayName', 'Engineers');

    $this->withHeader('Authorization', 'Bearer shipit-scim-token')
        ->patchJson('/scim/v2/Groups/engineers', [
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations' => [[
                'op' => 'replace',
                'path' => 'displayName',
                'value' => [[
                    'value' => 'Still Engineers',
                ]],
            ]],
        ])
        ->assertSuccessful()
        ->assertJsonPath('id', 'engineers');

    $this->withHeader('Authorization', 'Bearer shipit-scim-token')
        ->deleteJson('/scim/v2/Groups/engineers')
        ->assertNoContent();

    $this->withHeader('Authorization', 'Bearer shipit-scim-token')
        ->getJson('/scim/v2/Groups/missing-group')
        ->assertNotFound()
        ->assertJsonPath('schemas.0', 'urn:ietf:params:scim:api:messages:2.0:Error');

    expect(TestAuditSink::$events)->toHaveCount(1)
        ->and(TestAuditSink::$events[0]['event'])->toBe('scim_group_deleted');
});

function createScimGroupControllerProvider(): SsoProvider
{
    return SsoProvider::query()->firstOrCreate([
        'id' => 'provider-scim-group-controller-branch-coverage',
    ], [
        'tenant_id' => 1,
        'driver' => 'oidc',
        'scheme' => 'azure-group-branch-coverage',
        'display_name' => 'Acme Azure AD',
        'authority' => 'https://login.example.test/acme/v2.0',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'enabled' => true,
        'scim_enabled' => true,
        'scim_token_hash' => hash('sha256', 'shipit-scim-token'),
        'validate_issuer' => false,
    ]);
}
