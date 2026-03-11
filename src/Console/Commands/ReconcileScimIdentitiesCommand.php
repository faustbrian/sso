<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Console\Commands;

use Cline\SSO\Data\ProviderSearchCriteria;
use Cline\SSO\Enums\BooleanFilter;
use Cline\SSO\Jobs\ReconcileScimProviderMemberships;
use Cline\SSO\SsoManager;
use Illuminate\Console\Command;
use Override;
use Throwable;

use function __;
use function app;
use function collect;
use function count;
use function dispatch;
use function is_string;

/**
 * Reconciles SCIM-backed memberships for one or more configured providers.
 *
 * This command is the operator-facing entry point for replaying membership
 * synchronization after adapter changes, remote-directory drift, or queue
 * outages. It delegates provider selection to the manager, then either queues
 * one job per matching provider or invokes those jobs inline for immediate
 * diagnosis.
 *
 * The command intentionally targets only SCIM-enabled providers and optionally
 * narrows the run to explicit schemes. That keeps bulk maintenance focused on
 * the providers that actually participate in SCIM reconciliation.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class ReconcileScimIdentitiesCommand extends Command
{
    #[Override()]
    protected $signature = 'sso:reconcile-scim-identities
        {--scheme=* : Reconcile only the specified provider schemes}
        {--dispatch-sync : Reconcile synchronously instead of queueing jobs}';

    #[Override()]
    protected $description = '';

    public function __construct()
    {
        parent::__construct();

        $this->description = $this->message('sso::sso.commands.reconcile.description');
    }

    /**
     * Execute reconciliation for every matching SCIM-enabled provider.
     *
     * Providers are filtered by scheme when requested. In synchronous mode the
     * command invokes each job handler directly so operators can see failures in
     * the current process and receive a non-zero exit code when any provider
     * fails. In queued mode the command treats successful dispatch as success
     * and leaves execution to the configured queue workers.
     *
     * The summary output distinguishes the number of matched providers from the
     * number successfully reconciled so partial failures remain visible.
     */
    public function handle(SsoManager $sso): int
    {
        /** @var array<int, string> $schemes */
        $schemes = collect((array) $this->option('scheme'))
            ->filter(static fn (mixed $scheme): bool => is_string($scheme) && $scheme !== '')
            ->values()
            ->all();
        $dispatchSync = (bool) $this->option('dispatch-sync');

        $results = $sso->searchProviders(
            new ProviderSearchCriteria(
                schemes: $schemes,
                scimEnabled: BooleanFilter::True,
            ),
        );

        if ($results === []) {
            $this->info($this->message('sso::sso.commands.reconcile.no_matches'));

            return self::SUCCESS;
        }

        $processed = 0;
        $failed = 0;

        foreach ($results as $provider) {
            if ($dispatchSync) {
                try {
                    app()->call([new ReconcileScimProviderMemberships($provider->id), 'handle']);
                    ++$processed;
                    $this->line($this->message('sso::sso.commands.reconcile.reconciled', ['scheme' => $provider->scheme]));
                } catch (Throwable $exception) {
                    ++$failed;
                    $this->error($this->message('sso::sso.commands.reconcile.failed', [
                        'reason' => $exception->getMessage(),
                        'scheme' => $provider->scheme,
                    ]));
                }

                continue;
            }

            dispatch(
                new ReconcileScimProviderMemberships($provider->id),
            );
            ++$processed;
            $this->line($this->message('sso::sso.commands.reconcile.queued', ['scheme' => $provider->scheme]));
        }

        $this->info($this->message('sso::sso.commands.reconcile.summary', [
            'failed' => $failed,
            'processed' => count($results),
            'reconciled' => $processed,
        ]));

        return $failed > 0 ? self::FAILURE : self::SUCCESS;
    }

    /**
     * Translate a package language key into a concrete console message.
     *
     * Missing translations fall back to the key itself so command output still
     * contains a stable diagnostic identifier in partially configured
     * applications or during package development.
     *
     * @param array<string, scalar> $replace
     */
    private function message(string $key, array $replace = []): string
    {
        $message = __($key, $replace);

        return is_string($message) ? $message : $key;
    }
}
