<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Models\SsoProvider;
use Tests\Fixtures\TestScimUserAdapter;

it('rejects scim requests with an invalid bearer token', function (): void {
    createScimControllerProvider();

    $this->withHeader('Authorization', 'Bearer invalid-token')
        ->getJson('/scim/v2/ServiceProviderConfig')
        ->assertUnauthorized()
        ->assertJsonPath('schemas.0', 'urn:ietf:params:scim:api:messages:2.0:Error')
        ->assertJsonPath('status', '401');
});

it('shows replaces patches and rejects missing scim users', function (): void {
    createScimControllerProvider();

    TestScimUserAdapter::$users['user-1'] = [
        'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:User'],
        'id' => 'user-1',
        'externalId' => 'user-1',
        'userName' => 'first@example.test',
        'active' => true,
        'meta' => ['resourceType' => 'User'],
    ];

    $this->withHeader('Authorization', 'Bearer shipit-scim-token')
        ->getJson('/scim/v2/Users/user-1')
        ->assertSuccessful()
        ->assertJsonPath('userName', 'first@example.test');

    $this->withHeader('Authorization', 'Bearer shipit-scim-token')
        ->putJson('/scim/v2/Users/user-1', [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'userName' => 'second@example.test',
            'active' => true,
        ])
        ->assertSuccessful()
        ->assertJsonPath('userName', 'second@example.test');

    $this->withHeader('Authorization', 'Bearer shipit-scim-token')
        ->patchJson('/scim/v2/Users/user-1', [
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations' => [[
                'op' => 'replace',
                'path' => 'active',
                'value' => false,
            ]],
        ])
        ->assertSuccessful()
        ->assertJsonPath('active', false);

    $this->withHeader('Authorization', 'Bearer shipit-scim-token')
        ->getJson('/scim/v2/Users/missing-user')
        ->assertNotFound()
        ->assertJsonPath('schemas.0', 'urn:ietf:params:scim:api:messages:2.0:Error');
});

function createScimControllerProvider(): SsoProvider
{
    return SsoProvider::query()->firstOrCreate([
        'id' => 'provider-scim-controller-branch-coverage',
    ], [
        'tenant_id' => 1,
        'driver' => 'oidc',
        'scheme' => 'azure-branch-coverage',
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
