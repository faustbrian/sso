<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Contracts\ScimReconcilerInterface;
use Cline\SSO\Data\SsoProviderRecord;
use Cline\SSO\Jobs\ReconcileScimProviderMemberships;
use Cline\SSO\Models\SsoProvider;
use Illuminate\Support\Facades\Bus;
use Tests\Fixtures\TestAuditSink;
use Tests\Fixtures\TestScimReconciler;

it('reconciles scim providers synchronously', function (): void {
    $provider = SsoProvider::query()->create([
        'id' => 'provider-scim-sync',
        'tenant_id' => 1,
        'driver' => 'oidc',
        'scheme' => 'azure-acme',
        'display_name' => 'Acme Azure AD',
        'authority' => 'https://login.example.test/acme/v2.0',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'enabled' => true,
        'scim_enabled' => true,
    ]);

    $this->artisan('sso:reconcile-scim-identities', [
        '--scheme' => ['azure-acme'],
        '--dispatch-sync' => true,
    ])->assertSuccessful();

    expect(TestScimReconciler::$providerIds)->toBe([$provider->id])
        ->and(TestAuditSink::$events)->toHaveCount(1)
        ->and(TestAuditSink::$events[0]['event'])->toBe('provider_scim_reconciled');
});

it('queues scim reconciliation jobs by default', function (): void {
    $provider = SsoProvider::query()->create([
        'id' => 'provider-scim-queued',
        'tenant_id' => 1,
        'driver' => 'oidc',
        'scheme' => 'azure-acme-queued',
        'display_name' => 'Acme Azure AD',
        'authority' => 'https://login.example.test/acme/v2.0',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'enabled' => true,
        'scim_enabled' => true,
    ]);

    Bus::fake();

    $this->artisan('sso:reconcile-scim-identities', [
        '--scheme' => [$provider->scheme],
    ])->assertSuccessful();

    Bus::assertDispatched(ReconcileScimProviderMemberships::class, static fn (ReconcileScimProviderMemberships $job): bool => $job->providerId === $provider->id);
});

it('returns success when no scim providers match the reconciliation filters', function (): void {
    Bus::fake();

    $this->artisan('sso:reconcile-scim-identities', [
        '--scheme' => ['missing-provider'],
    ])->assertSuccessful();

    Bus::assertNothingDispatched();
});

it('returns failure when synchronous reconciliation throws', function (): void {
    SsoProvider::query()->create([
        'id' => 'provider-scim-failure',
        'tenant_id' => 1,
        'driver' => 'oidc',
        'scheme' => 'azure-scim-failure',
        'display_name' => 'Acme Azure AD',
        'authority' => 'https://login.example.test/acme/v2.0',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'enabled' => true,
        'scim_enabled' => true,
    ]);

    $this->app->instance(ScimReconcilerInterface::class, new class() implements ScimReconcilerInterface
    {
        public function reconcile(SsoProviderRecord $provider): array
        {
            throw new RuntimeException('SCIM reconciliation failed');
        }
    });

    $this->artisan('sso:reconcile-scim-identities', [
        '--scheme' => ['azure-scim-failure'],
        '--dispatch-sync' => true,
    ])->assertFailed();

    expect(TestAuditSink::$events)->toHaveCount(1)
        ->and(TestAuditSink::$events[0]['event'])->toBe('provider_scim_reconcile_failed');
});
