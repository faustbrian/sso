<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Jobs\RefreshSsoProviderMetadata;
use Cline\SSO\Models\SsoProvider;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Tests\Fixtures\TestAuditSink;

it('refreshes oidc provider metadata synchronously', function (): void {
    $provider = SsoProvider::query()->create([
        'id' => 'provider-oidc',
        'tenant_id' => 1,
        'driver' => 'oidc',
        'scheme' => 'azure-acme',
        'display_name' => 'Acme Azure AD',
        'authority' => 'https://login.example.test/acme/v2.0',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'valid_issuer' => 'https://login.example.test/acme/v2.0',
        'validate_issuer' => true,
        'enabled' => true,
    ]);

    Cache::put('sso:oidc:discovery:'.sha1('https://login.example.test/acme/v2.0'), ['stale' => true], now()->addHour());
    Cache::put('sso:oidc:jwks:'.sha1('https://login.example.test/acme/discovery/keys'), ['stale' => true], now()->addHour());

    Http::fake([
        'https://login.example.test/acme/v2.0/.well-known/openid-configuration' => Http::response([
            'issuer' => 'https://login.example.test/acme/v2.0',
            'authorization_endpoint' => 'https://login.example.test/acme/v2.0/authorize',
            'token_endpoint' => 'https://login.example.test/acme/v2.0/token',
            'jwks_uri' => 'https://login.example.test/acme/discovery/keys',
        ]),
        'https://login.example.test/acme/discovery/keys' => Http::response([
            'keys' => [[
                'kid' => 'key-1',
                'kty' => 'RSA',
                'use' => 'sig',
                'n' => 'sXch4MGL7jM8oS93Z4I4L7zQ6ArlTc95xJMu38xpv8uKXu95syEHCqB6f0GO6zkRgZNpmjQe7YQDdyCjTiMQuYzfoalGexiLRNvKcJsteVEh9UpAJZciV06P88eaJEqn3Ejj6inUeJ8V4aHcRUW2KIiMzFxLpy0X58F3RrgPf63HgFUsVTNff7kwh28ykVfoCENKz7LxyzKDn5XxhxL7sRKqzZo4PMBVXgS5aXoaZySUdkGFUTkOcJCIZy9FHn5Vf3L7hIwrKyYVJZZzKzbwQ6vurIWBLL8GMDIS9ZhDJW60Agw7P3cu6UytzszbmWzxubUoilKx2oyS9MhUlCT3VkQ',
                'e' => 'AQAB',
            ]],
        ]),
    ]);

    $this->artisan('sso:refresh-metadata', [
        '--scheme' => ['azure-acme'],
        '--dispatch-sync' => true,
    ])->assertSuccessful();

    expect($provider->fresh()->last_metadata_refreshed_at)->not->toBeNull()
        ->and($provider->fresh()->last_metadata_refresh_error)->toBeNull()
        ->and(Cache::get('sso:oidc:discovery:'.sha1('https://login.example.test/acme/v2.0')))
        ->toMatchArray(['issuer' => 'https://login.example.test/acme/v2.0'])
        ->and(TestAuditSink::$events)->toHaveCount(1)
        ->and(TestAuditSink::$events[0]['event'])->toBe('provider_metadata_refreshed');
});

it('queues metadata refresh jobs by default', function (): void {
    $provider = SsoProvider::query()->create([
        'id' => 'provider-queued',
        'tenant_id' => 1,
        'driver' => 'oidc',
        'scheme' => 'azure-queued',
        'display_name' => 'Queued Provider',
        'authority' => 'https://login.example.test/queued/v2.0',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'enabled' => true,
    ]);

    Bus::fake();

    $this->artisan('sso:refresh-metadata', [
        '--scheme' => [$provider->scheme],
    ])->assertSuccessful();

    Bus::assertDispatched(RefreshSsoProviderMetadata::class, static fn (RefreshSsoProviderMetadata $job): bool => $job->providerId === $provider->id);
});

it('returns success when no providers match the metadata refresh filters', function (): void {
    Bus::fake();

    $this->artisan('sso:refresh-metadata', [
        '--scheme' => ['missing-provider'],
    ])->assertSuccessful();

    Bus::assertNothingDispatched();
});

it('returns failure when synchronous metadata refresh throws', function (): void {
    $provider = SsoProvider::query()->create([
        'id' => 'provider-refresh-failure',
        'tenant_id' => 1,
        'driver' => 'oidc',
        'scheme' => 'azure-refresh-failure',
        'display_name' => 'Acme Azure AD',
        'authority' => 'https://login.example.test/acme/v2.0',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'enabled' => true,
        'validate_issuer' => false,
    ]);

    Http::fake([
        'https://login.example.test/acme/v2.0/.well-known/openid-configuration' => Http::response([
            'authorization_endpoint' => 'https://login.example.test/oauth2/v2.0/authorize',
            'jwks_uri' => 'https://login.example.test/discovery/v2.0/keys',
        ]),
    ]);

    $this->artisan('sso:refresh-metadata', [
        '--scheme' => [$provider->scheme],
        '--dispatch-sync' => true,
    ])->assertFailed();

    expect($provider->fresh()->last_metadata_refresh_failed_at)->not->toBeNull()
        ->and($provider->fresh()->last_metadata_refresh_error)->not->toBeNull()
        ->and(TestAuditSink::$events)->toHaveCount(1)
        ->and(TestAuditSink::$events[0]['event'])->toBe('provider_metadata_refresh_failed');
});
