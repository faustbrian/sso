<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Contracts\AuditSinkInterface;
use Cline\SSO\Contracts\ScimReconcilerInterface;
use Cline\SSO\Data\SsoProviderRecord;
use Cline\SSO\Jobs\ReconcileScimProviderMemberships;
use Cline\SSO\Models\SsoProvider;
use Cline\SSO\SsoManager;
use Tests\Fixtures\TestAuditSink;

it('treats a missing provider as a no op for scim reconciliation jobs', function (): void {
    $job = new ReconcileScimProviderMemberships('missing-provider');

    $job->handle(
        resolve(ScimReconcilerInterface::class),
        resolve(AuditSinkInterface::class),
        resolve(SsoManager::class),
    );

    expect(TestAuditSink::$events)->toBe([]);
});

it('records reconciliation failures before rethrowing the job exception', function (): void {
    $provider = SsoProvider::query()->create([
        'id' => 'provider-reconcile-job-failure',
        'tenant_id' => 1,
        'driver' => 'oidc',
        'scheme' => 'azure-reconcile-job-failure',
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
            throw new RuntimeException('SCIM reconcile job failed');
        }
    });

    expect(fn (): mixed => new ReconcileScimProviderMemberships($provider->id)->handle(
        resolve(ScimReconcilerInterface::class),
        resolve(AuditSinkInterface::class),
        resolve(SsoManager::class),
    ))->toThrow(RuntimeException::class, 'SCIM reconcile job failed');

    expect(TestAuditSink::$events)->toHaveCount(1)
        ->and(TestAuditSink::$events[0]['event'])->toBe('provider_scim_reconcile_failed');
});
