<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Console\Commands;

use Cline\SSO\Contracts\AuditSinkInterface;
use Cline\SSO\Data\OwnerReference;
use Cline\SSO\Data\ProviderSearchCriteria;
use Cline\SSO\Enums\BooleanFilter;
use Cline\SSO\SsoManager;
use Illuminate\Console\Command;
use Override;

use function __;
use function collect;
use function count;
use function is_string;

/**
 * Emergency command for disabling SSO enforcement on matching providers.
 *
 * This recovery flow exists for incident-response scenarios where an identity
 * provider misconfiguration would otherwise lock administrators out of the
 * application. It can target providers by owner scope or explicit scheme and,
 * when requested, disable the affected providers entirely after clearing
 * mandatory SSO enforcement.
 *
 * The command is intentionally conservative. It refuses to run without an
 * explicit owner scope or scheme filter so operators cannot accidentally relax
 * enforcement across every configured provider. Its side effects are limited
 * to provider updates and audit events; it does not try to repair remote
 * identity state or mutate principal links.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class RecoverSsoAccessCommand extends Command
{
    #[Override()]
    protected $signature = 'sso:recover-access
        {ownerType? : Recover providers for the specified owner type}
        {ownerId? : Recover providers for the specified owner id}
        {--scheme=* : Recover only the specified provider schemes}
        {--disable-provider : Disable recovered providers in addition to clearing enforcement}';

    #[Override()]
    protected $description = '';

    public function __construct()
    {
        parent::__construct();

        $this->description = $this->message('sso::sso.commands.recover.description');
    }

    /**
     * Apply recovery overrides and emit an audit event for each affected
     * provider.
     *
     * The command first resolves the provider set using the safest filter that
     * matches the supplied arguments. Tenant-scoped recovery targets only
     * providers currently enforcing SSO, while scheme-based recovery can be
     * broader because the operator has already named the affected providers
     * explicitly.
     *
     * Every successful override is audited so applications can preserve an
     * operational trail for emergency access changes. When
     * `--disable-provider` is present, the command also clears `enabled` and
     * `is_default` to prevent the recovered provider from being selected again
     * automatically while the upstream incident is being resolved.
     */
    public function handle(AuditSinkInterface $audit, SsoManager $sso): int
    {
        /** @var null|string $ownerType */
        $ownerType = $this->argument('ownerType');

        /** @var null|string $ownerId */
        $ownerId = $this->argument('ownerId');

        /** @var array<int, string> $schemes */
        $schemes = collect((array) $this->option('scheme'))
            ->filter(static fn (mixed $scheme): bool => is_string($scheme) && $scheme !== '')
            ->values()
            ->all();
        $disableProviders = (bool) $this->option('disable-provider');

        if ($schemes === [] && ($ownerType === null || $ownerId === null)) {
            $this->error($this->message('sso::sso.commands.recover.missing_criteria'));

            return self::FAILURE;
        }

        $results = $sso->searchProviders(
            new ProviderSearchCriteria(
                enforceSso: $schemes === [] ? BooleanFilter::True : BooleanFilter::Any,
                owner: $schemes === [] ? new OwnerReference((string) $ownerType, (string) $ownerId) : null,
                schemes: $schemes,
            ),
        );

        if ($results === []) {
            $this->warn($this->message('sso::sso.commands.recover.no_matches'));

            return self::FAILURE;
        }

        foreach ($results as $provider) {
            $sso->updateProvider($provider->id, [
                'enforce_sso' => false,
                'enabled' => $disableProviders ? false : $provider->enabled,
                'is_default' => $disableProviders ? false : $provider->isDefault,
            ]);

            $audit->record('provider_recovery_override_applied', $provider, [
                'disabled_provider' => $disableProviders,
            ]);

            $this->line($this->message('sso::sso.commands.recover.recovered', ['scheme' => $provider->scheme]));
        }

        $this->info($this->message('sso::sso.commands.recover.summary', ['count' => count($results)]));

        return self::SUCCESS;
    }

    /**
     * Translate a package language key into a concrete console message.
     *
     * Missing translations fall back to the key itself so emergency tooling
     * still produces actionable output during partial deployments or broken
     * localization setups. That failure mode is intentional because access
     * recovery commands must remain operable even when localization assets are
     * out of sync with the deployed code.
     *
     * @param array<string, scalar> $replace
     */
    private function message(string $key, array $replace = []): string
    {
        $message = __($key, $replace);

        return is_string($message) ? $message : $key;
    }
}
