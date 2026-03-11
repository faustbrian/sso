<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Jobs;

use Cline\SSO\Contracts\AuditSinkInterface;
use Cline\SSO\Data\SsoProviderRecord;
use Cline\SSO\SsoManager;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Throwable;

use function now;

/**
 * Queue job that refreshes cached remote metadata for one provider record.
 *
 * Metadata refresh is intentionally isolated behind a queueable job because it
 * may perform remote network calls, signature-key discovery, and provider
 * validation. The job updates operational timestamps so administrators can see
 * both the latest successful refresh and the latest failure reason.
 *
 * Like the reconciliation job, it carries only the provider identifier so the
 * queued payload does not go stale when provider configuration changes.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class RefreshSsoProviderMetadata implements ShouldQueue
{
    use Queueable;

    public function __construct(
        public readonly string $providerId,
    ) {}

    /**
     * Refresh remote metadata when the provider still exists.
     *
     * Queue jobs can run after a provider has been deleted, which is treated as
     * a safe no-op. On failure the provider record is updated with error state
     * before the exception is rethrown so normal queue retry behavior remains
     * available. On success the error fields are explicitly cleared so stale
     * metadata failures do not survive a later successful refresh.
     */
    public function handle(
        AuditSinkInterface $audit,
        SsoManager $sso,
    ): void {
        $provider = $sso->findProviderById($this->providerId);

        if (!$provider instanceof SsoProviderRecord) {
            return;
        }

        try {
            $details = $sso->refreshMetadata($provider);

            $sso->updateProvider($provider->id, [
                'last_metadata_refreshed_at' => now(),
                'last_metadata_refresh_failed_at' => null,
                'last_metadata_refresh_error' => null,
            ]);

            $audit->record('provider_metadata_refreshed', $provider, [
                'details' => $details,
            ]);
        } catch (Throwable $throwable) {
            $sso->updateProvider($provider->id, [
                'last_metadata_refresh_failed_at' => now(),
                'last_metadata_refresh_error' => $throwable->getMessage(),
            ]);

            $audit->record('provider_metadata_refresh_failed', $provider, [
                'reason' => $throwable->getMessage(),
            ]);

            throw $throwable;
        }
    }
}
