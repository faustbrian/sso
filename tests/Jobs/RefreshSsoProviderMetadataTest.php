<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Contracts\AuditSinkInterface;
use Cline\SSO\Jobs\RefreshSsoProviderMetadata;
use Cline\SSO\Models\SsoProvider;
use Cline\SSO\SsoManager;
use Illuminate\Support\Facades\Http;
use Tests\Fixtures\TestAuditSink;

it('treats a missing provider as a no op for metadata refresh jobs', function (): void {
    $job = new RefreshSsoProviderMetadata('missing-provider');

    $job->handle(
        resolve(AuditSinkInterface::class),
        resolve(SsoManager::class),
    );

    expect(TestAuditSink::$events)->toBe([]);
});

it('records refresh failures before rethrowing the metadata exception', function (): void {
    $provider = SsoProvider::query()->create([
        'id' => 'provider-refresh-job-failure',
        'tenant_id' => 1,
        'driver' => 'oidc',
        'scheme' => 'azure-refresh-job-failure',
        'display_name' => 'Acme Azure AD',
        'authority' => 'https://login.example.test/job-failure/v2.0',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'enabled' => true,
        'validate_issuer' => false,
    ]);

    Http::fake([
        'https://login.example.test/job-failure/v2.0/.well-known/openid-configuration' => Http::response([
            'authorization_endpoint' => 'https://login.example.test/oauth2/v2.0/authorize',
            'jwks_uri' => 'https://login.example.test/discovery/v2.0/keys',
        ]),
    ]);

    expect(fn (): mixed => new RefreshSsoProviderMetadata($provider->id)->handle(
        resolve(AuditSinkInterface::class),
        resolve(SsoManager::class),
    ))->toThrow(RuntimeException::class);

    expect($provider->fresh()->last_metadata_refresh_failed_at)->not->toBeNull()
        ->and($provider->fresh()->last_metadata_refresh_error)->not->toBeNull()
        ->and(TestAuditSink::$events)->toHaveCount(1)
        ->and(TestAuditSink::$events[0]['event'])->toBe('provider_metadata_refresh_failed');
});
