<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Console\Commands;

use Cline\SSO\Data\ProviderSearchCriteria;
use Cline\SSO\Jobs\RefreshSsoProviderMetadata;
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
 * Refreshes imported metadata for matching SSO providers.
 *
 * Administrative users can use this command after upstream certificate,
 * endpoint, or issuer changes to repopulate provider metadata without waiting
 * for normal background refresh cycles. It follows the same operational shape
 * as the reconciliation command: resolve providers through the manager, then
 * either queue a refresh job per provider or invoke the job inline.
 *
 * This makes the command suitable both for routine maintenance in queued
 * environments and for direct diagnostics when an operator needs immediate
 * feedback from a specific provider refresh.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class RefreshSsoProviderMetadataCommand extends Command
{
    #[Override()]
    protected $signature = 'sso:refresh-metadata
        {--scheme=* : Refresh only the specified provider schemes}
        {--dispatch-sync : Refresh synchronously instead of queueing jobs}';

    #[Override()]
    protected $description = '';

    public function __construct()
    {
        parent::__construct();

        $this->description = $this->message('sso::sso.commands.refresh.description');
    }

    /**
     * Queue or execute metadata refresh jobs for every matching provider.
     *
     * Synchronous mode surfaces per-provider failures directly in the console
     * and returns a failing exit code when any refresh throws. Asynchronous mode
     * treats successful job dispatch as success and is intended for normal
     * maintenance where queue workers will perform the remote metadata fetches
     * out of band.
     *
     * The summary output reports both processed and failed providers so
     * operators can distinguish between an empty match set, partial failure, and
     * a fully successful refresh run.
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
            ),
        );

        if ($results === []) {
            $this->info($this->message('sso::sso.commands.refresh.no_matches'));

            return self::SUCCESS;
        }

        $refreshed = 0;
        $failed = 0;

        foreach ($results as $provider) {
            if ($dispatchSync) {
                try {
                    app()->call([new RefreshSsoProviderMetadata($provider->id), 'handle']);
                    ++$refreshed;
                    $this->line($this->message('sso::sso.commands.refresh.refreshed', ['scheme' => $provider->scheme]));
                } catch (Throwable $exception) {
                    ++$failed;
                    $this->error($this->message('sso::sso.commands.refresh.failed', [
                        'scheme' => $provider->scheme,
                        'reason' => $exception->getMessage(),
                    ]));
                }

                continue;
            }

            dispatch(
                new RefreshSsoProviderMetadata($provider->id),
            );
            ++$refreshed;
            $this->line($this->message('sso::sso.commands.refresh.queued', ['scheme' => $provider->scheme]));
        }

        $this->info($this->message('sso::sso.commands.refresh.summary', [
            'failed' => $failed,
            'processed' => count($results),
            'refreshed' => $refreshed,
        ]));

        return $failed > 0 ? self::FAILURE : self::SUCCESS;
    }

    /**
     * Translate a package language key into a concrete console message.
     *
     * Missing translations fall back to the key itself so operators still see
     * a stable diagnostic identifier instead of an empty string or `null`
     * output.
     *
     * @param array<string, scalar> $replace
     */
    private function message(string $key, array $replace = []): string
    {
        $message = __($key, $replace);

        return is_string($message) ? $message : $key;
    }
}
