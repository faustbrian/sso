<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Models\SsoProvider;
use Tests\Fixtures\TestAuditSink;
use Tests\Fixtures\TestUser;

it('disables enforced sso for matching owner providers through the recovery command', function (): void {
    $owner = TestUser::query()->create([
        'email' => 'recover-org@example.test',
        'name' => 'Recover Owner',
        'password' => 'secret',
    ]);

    $provider = SsoProvider::query()->create([
        'id' => 'provider-recover',
        'tenant_id' => $owner->id,
        'driver' => 'oidc',
        'scheme' => 'azure-acme',
        'display_name' => 'Acme Azure AD',
        'authority' => 'https://login.example.test/acme/v2.0',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'valid_issuer' => 'https://login.example.test/acme/v2.0',
        'validate_issuer' => true,
        'enabled' => true,
        'enforce_sso' => true,
        'last_validation_succeeded_at' => now(),
    ]);

    $this->artisan('sso:recover-access', [
        'ownerType' => $owner->getMorphClass(),
        'ownerId' => (string) $owner->id,
        '--disable-provider' => true,
    ])->assertSuccessful();

    expect($provider->fresh()->enforce_sso)->toBeFalse()
        ->and($provider->fresh()->enabled)->toBeFalse()
        ->and(TestAuditSink::$events)->toHaveCount(1)
        ->and(TestAuditSink::$events[0]['event'])->toBe('provider_recovery_override_applied');
});

it('fails recovery when no owner or scheme criteria are provided', function (): void {
    $this->artisan('sso:recover-access')->assertFailed();
});

it('fails recovery when no providers match the supplied owner scope', function (): void {
    $this->artisan('sso:recover-access', [
        'ownerType' => 'tests.fixtures.test_user',
        'ownerId' => '999',
    ])->assertFailed();
});

it('recovers matching providers by scheme without disabling them', function (): void {
    $provider = SsoProvider::query()->create([
        'id' => 'provider-recover-scheme',
        'tenant_id' => 1,
        'driver' => 'oidc',
        'scheme' => 'azure-recover-scheme',
        'display_name' => 'Acme Azure AD',
        'authority' => 'https://login.example.test/acme/v2.0',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'enabled' => true,
        'is_default' => true,
        'enforce_sso' => true,
    ]);

    $this->artisan('sso:recover-access', [
        '--scheme' => [$provider->scheme],
    ])->assertSuccessful();

    expect($provider->fresh()->enforce_sso)->toBeFalse()
        ->and($provider->fresh()->enabled)->toBeTrue()
        ->and($provider->fresh()->is_default)->toBeTrue()
        ->and(TestAuditSink::$events)->toHaveCount(1)
        ->and(TestAuditSink::$events[0]['event'])->toBe('provider_recovery_override_applied');
});
