<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Carbon\CarbonImmutable;
use Cline\SSO\Data\OwnerReference;
use Cline\SSO\Data\SsoProviderRecord;

it('normalizes provider settings to an array map', function (): void {
    $record = makeProviderRecord(settings: null);

    expect($record->settingsMap())->toBe([]);
});

it('returns filtered scim managed group ids in their configured order', function (): void {
    $record = makeProviderRecord(settings: [
        'scim_managed_group_ids' => ['engineering', '', 'support', '0'],
    ]);

    expect($record->scimManagedGroupIds())->toBe([
        'engineering',
        'support',
        '0',
    ]);
});

it('preserves owner and timestamp data', function (): void {
    $owner = new OwnerReference('teams', '7');
    $lastUsedAt = CarbonImmutable::parse('2026-03-11 10:00:00');
    $record = makeProviderRecord(owner: $owner, lastUsedAt: $lastUsedAt);

    expect($record->owner)->toBe($owner)
        ->and($record->lastUsedAt?->toIso8601String())
        ->toBe($lastUsedAt->toIso8601String());
});

function makeProviderRecord(
    ?OwnerReference $owner = null,
    ?CarbonImmutable $lastUsedAt = null,
    mixed $settings = [],
): SsoProviderRecord {
    return new SsoProviderRecord(
        id: 'provider-1',
        driver: 'oidc',
        scheme: 'acme',
        displayName: 'Acme',
        authority: 'https://issuer.example.test',
        clientId: 'client-id',
        clientSecret: 'client-secret',
        validIssuer: null,
        validateIssuer: false,
        enabled: true,
        isDefault: false,
        enforceSso: false,
        scimEnabled: true,
        scimTokenHash: null,
        scimLastUsedAt: null,
        lastUsedAt: $lastUsedAt,
        lastLoginSucceededAt: null,
        lastLoginFailedAt: null,
        lastFailureReason: null,
        lastMetadataRefreshedAt: null,
        lastMetadataRefreshFailedAt: null,
        lastMetadataRefreshError: null,
        lastValidatedAt: null,
        lastValidationSucceededAt: null,
        lastValidationFailedAt: null,
        lastValidationError: null,
        secretRotatedAt: null,
        owner: $owner,
        settings: $settings,
    );
}
