<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Data;

use Carbon\CarbonInterface;

use function collect;
use function is_array;

/**
 * Immutable read model describing a configured SSO provider.
 *
 * Repository implementations return this projection instead of Eloquent models
 * so the rest of the package can reason about provider state without depending
 * on persistence concerns. The record carries both the configuration required
 * to execute protocol flows and the operational timestamps used for audit,
 * metadata refresh, validation, and SCIM activity reporting.
 *
 * This type sits at the center of the package. Managers, strategies, jobs,
 * middleware, and controllers all pass it around as the canonical view of a
 * provider's current persisted state. The record therefore mixes relatively
 * static configuration, such as authority and client credentials, with
 * append-only operational metadata that explains how the provider has behaved
 * over time.
 *
 * @author Brian Faust <brian@cline.sh>
 * @phpstan-type SsoProviderSettings array<string, mixed>
 * @psalm-immutable
 */
final readonly class SsoProviderRecord
{
    /**
     * @param null|SsoProviderSettings $settings Driver-specific configuration
     *                                           already normalized for runtime
     *                                           use; callers should treat this
     *                                           as a settings bag whose keys are
     *                                           interpreted by strategies and
     *                                           jobs, not by generic consumers
     */
    public function __construct(
        public string $id,
        public string $driver,
        public string $scheme,
        public string $displayName,
        public string $authority,
        public string $clientId,
        public string $clientSecret,
        public ?string $validIssuer,
        public bool $validateIssuer,
        public bool $enabled,
        public bool $isDefault,
        public bool $enforceSso,
        public bool $scimEnabled,
        public ?string $scimTokenHash,
        public ?CarbonInterface $scimLastUsedAt,
        public ?CarbonInterface $lastUsedAt,
        public ?CarbonInterface $lastLoginSucceededAt,
        public ?CarbonInterface $lastLoginFailedAt,
        public ?string $lastFailureReason,
        public ?CarbonInterface $lastMetadataRefreshedAt,
        public ?CarbonInterface $lastMetadataRefreshFailedAt,
        public ?string $lastMetadataRefreshError,
        public ?CarbonInterface $lastValidatedAt,
        public ?CarbonInterface $lastValidationSucceededAt,
        public ?CarbonInterface $lastValidationFailedAt,
        public ?string $lastValidationError,
        public ?CarbonInterface $secretRotatedAt,
        public ?OwnerReference $owner,
        public ?array $settings,
        public int $externalIdentityCount = 0,
    ) {}

    /**
     * Return provider settings as a normalized associative array.
     *
     * Persisted settings may be missing or malformed when records are edited
     * externally; callers receive an empty map instead of needing to guard
     * against non-array values at every read site. This makes the settings bag
     * safe to consume in strategies and jobs that expect associative-array
     * semantics. The method intentionally does not attempt deeper coercion of
     * nested values because driver-specific consumers are the correct place to
     * enforce those invariants.
     *
     * @return SsoProviderSettings
     */
    public function settingsMap(): array
    {
        if (!is_array($this->settings)) {
            return [];
        }

        return $this->settings;
    }

    /**
     * Return the configured SCIM-managed group identifiers for the provider.
     *
     * Empty entries are removed so reconciliation jobs can treat the result as
     * a clean list of group identifiers owned by the provider configuration.
     * Non-array or partially malformed settings degrade to an empty list rather
     * than causing every caller to repeat defensive parsing logic. The returned
     * values preserve the configured order after empty entries are stripped so
     * adapter and synchronization layers can apply deterministic reconciliation
     * behavior.
     *
     * @return array<int, string>
     */
    public function scimManagedGroupIds(): array
    {
        /** @var array<int, string> $groupIds */
        $groupIds = $this->settingsMap()['scim_managed_group_ids'] ?? [];

        return collect($groupIds)
            ->filter(static fn (string $groupId): bool => $groupId !== '')
            ->values()
            ->all();
    }
}
