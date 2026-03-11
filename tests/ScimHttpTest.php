<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Models\SsoProvider;
use Tests\Fixtures\TestScimGroupAdapter;
use Tests\Fixtures\TestScimUserAdapter;

it('rejects scim requests without a bearer token', function (): void {
    $this->getJson('/scim/v2/ServiceProviderConfig')
        ->assertUnauthorized()
        ->assertJsonPath('schemas.0', 'urn:ietf:params:scim:api:messages:2.0:Error')
        ->assertJsonPath('status', '401');
});

it('serves scim service provider config behind bearer auth', function (): void {
    createScimProvider([
        'id' => 'provider-1',
        'driver' => 'oidc',
        'scheme' => 'azure-acme',
        'display_name' => 'Acme Azure AD',
        'authority' => 'https://login.example.test/acme/v2.0',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'enabled' => true,
        'scim_enabled' => true,
        'scim_token_hash' => hash('sha256', 'shipit-scim-token'),
        'validate_issuer' => false,
    ]);

    $this->withHeader('Authorization', 'Bearer shipit-scim-token')
        ->getJson('/scim/v2/ServiceProviderConfig')
        ->assertSuccessful()
        ->assertHeader('Content-Type', 'application/scim+json')
        ->assertJsonPath('schemas.0', 'urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig')
        ->assertJsonPath('authenticationSchemes.0.name', 'OAuth Bearer Token')
        ->assertJsonPath('patch.supported', true);
});

it('returns the supported scim schemas and resource types', function (): void {
    createScimProvider([
        'id' => 'provider-schemas',
        'driver' => 'oidc',
        'scheme' => 'azure-schemas',
        'display_name' => 'Acme Azure AD',
        'authority' => 'https://login.example.test/acme/v2.0',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'enabled' => true,
        'scim_enabled' => true,
        'scim_token_hash' => hash('sha256', 'shipit-scim-token'),
        'validate_issuer' => false,
    ]);

    $this->withHeader('Authorization', 'Bearer shipit-scim-token')
        ->getJson('/scim/v2/Schemas')
        ->assertSuccessful()
        ->assertJsonPath('totalResults', 4)
        ->assertJsonPath('Resources.0.id', 'urn:ietf:params:scim:schemas:core:2.0:User');

    $this->withHeader('Authorization', 'Bearer shipit-scim-token')
        ->getJson('/scim/v2/ResourceTypes')
        ->assertSuccessful()
        ->assertJsonPath('totalResults', 2)
        ->assertJsonPath('Resources.0.schema', 'urn:ietf:params:scim:schemas:core:2.0:User');
});

it('returns scim validation errors as scim error payloads', function (): void {
    createScimProvider([
        'id' => 'provider-validation',
        'driver' => 'oidc',
        'scheme' => 'azure-validation',
        'display_name' => 'Acme Azure AD',
        'authority' => 'https://login.example.test/acme/v2.0',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'enabled' => true,
        'scim_enabled' => true,
        'scim_token_hash' => hash('sha256', 'shipit-scim-token'),
        'validate_issuer' => false,
    ]);

    $this->withHeader('Authorization', 'Bearer shipit-scim-token')
        ->postJson('/scim/v2/Users', [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'active' => true,
        ])
        ->assertStatus(422)
        ->assertHeader('Content-Type', 'application/scim+json')
        ->assertJsonPath('schemas.0', 'urn:ietf:params:scim:api:messages:2.0:Error')
        ->assertJsonPath('status', '422');
});

it('creates and lists scim users and groups through adapters', function (): void {
    createScimProvider([
        'id' => 'provider-1',
        'driver' => 'oidc',
        'scheme' => 'azure-acme',
        'display_name' => 'Acme Azure AD',
        'authority' => 'https://login.example.test/acme/v2.0',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'enabled' => true,
        'scim_enabled' => true,
        'scim_token_hash' => hash('sha256', 'shipit-scim-token'),
        'validate_issuer' => false,
    ]);

    $this->withHeader('Authorization', 'Bearer shipit-scim-token')
        ->postJson('/scim/v2/Users', [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'externalId' => 'user-1',
            'userName' => 'scim@example.test',
        ])
        ->assertCreated()
        ->assertJsonPath('id', 'user-1');

    $this->withHeader('Authorization', 'Bearer shipit-scim-token')
        ->postJson('/scim/v2/Groups', [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:Group'],
            'displayName' => 'Engineers',
        ])
        ->assertCreated()
        ->assertJsonPath('displayName', 'Engineers');

    $this->withHeader('Authorization', 'Bearer shipit-scim-token')
        ->getJson('/scim/v2/Users')
        ->assertSuccessful()
        ->assertJsonPath('totalResults', 1);

    $this->withHeader('Authorization', 'Bearer shipit-scim-token')
        ->getJson('/scim/v2/Groups')
        ->assertSuccessful()
        ->assertJsonPath('totalResults', 1);

    expect(TestScimUserAdapter::$users)->toHaveCount(1)
        ->and(TestScimGroupAdapter::$groups)->toHaveCount(1);
});

function createScimProvider(array $attributes): SsoProvider
{
    return SsoProvider::query()->create([
        'tenant_id' => 1,
        ...$attributes,
    ]);
}
