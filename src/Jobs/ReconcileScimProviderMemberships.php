<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Jobs;

use Cline\SSO\Contracts\AuditSinkInterface;
use Cline\SSO\Contracts\ScimReconcilerInterface;
use Cline\SSO\Data\SsoProviderRecord;
use Cline\SSO\SsoManager;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Throwable;

/**
 * Queue job that replays SCIM group reconciliation for a single provider.
 *
 * The command layer and any scheduled maintenance can dispatch this job
 * without needing to know how the application maps remote groups to local
 * roles or memberships. Audit events are emitted for both success and failure
 * so operators can reconstruct what happened for a provider after the fact.
 *
 * The job intentionally carries only the provider identifier. That keeps the
 * queued payload stable even if provider details change between dispatch and
 * execution.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class ReconcileScimProviderMemberships implements ShouldQueue
{
    use Queueable;

    public function __construct(
        public readonly string $providerId,
    ) {}

    /**
     * Run reconciliation if the referenced provider still exists.
     *
     * Missing providers are treated as a no-op because queued work can outlive
     * configuration changes. Reconciliation failures are audited before the
     * exception is rethrown so queue retry and failure handling still apply.
     * Successful reconciliation records the structured summary returned by the
     * application-defined reconciler.
     */
    public function handle(
        ScimReconcilerInterface $reconciler,
        AuditSinkInterface $audit,
        SsoManager $sso,
    ): void {
        $provider = $sso->findProviderById($this->providerId);

        if (!$provider instanceof SsoProviderRecord) {
            return;
        }

        try {
            $result = $reconciler->reconcile($provider);

            $audit->record('provider_scim_reconciled', $provider, [
                'result' => $result,
            ]);
        } catch (Throwable $throwable) {
            $audit->record('provider_scim_reconcile_failed', $provider, [
                'reason' => $throwable->getMessage(),
            ]);

            throw $throwable;
        }
    }
}
