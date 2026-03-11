<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Models\ExternalIdentity;
use Cline\SSO\Models\SsoProvider;
use Tests\Fixtures\TestUser;

it('resolves configured principal and provider relationships', function (): void {
    $owner = TestUser::query()->create([
        'email' => 'owner@example.test',
        'name' => 'Owner',
    ]);
    $principal = TestUser::query()->create([
        'email' => 'principal@example.test',
        'name' => 'Principal',
    ]);
    $provider = SsoProvider::query()->create([
        'tenant_id' => (string) $owner->id,
        'driver' => 'oidc',
        'scheme' => 'azure-acme',
        'display_name' => 'Acme Azure',
        'authority' => 'https://login.example.test',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'enabled' => true,
        'validate_issuer' => false,
    ]);

    $identity = ExternalIdentity::query()->create([
        'user_id' => (string) $principal->id,
        'sso_provider_id' => $provider->id,
        'issuer' => 'https://issuer.example.test',
        'subject' => 'subject-1',
        'email_snapshot' => $principal->email,
    ]);

    expect($identity->getTable())->toBe('external_identities')
        ->and($identity->principal?->is($principal))->toBeTrue()
        ->and($identity->provider->is($provider))->toBeTrue()
        ->and($provider->externalIdentities)->toHaveCount(1);
});
