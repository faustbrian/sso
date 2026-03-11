<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Models\SsoProvider;
use Tests\Fixtures\TestUser;

it('covers provider model helpers and casts', function (): void {
    $owner = TestUser::query()->create([
        'email' => 'owner@example.test',
        'name' => 'Owner',
    ]);

    $provider = SsoProvider::query()->create([
        'tenant_id' => (string) $owner->id,
        'driver' => 'oidc',
        'scheme' => 'azure-acme',
        'display_name' => 'Acme Azure',
        'authority' => 'https://login.example.test',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'enabled' => true,
        'validate_issuer' => false,
        'settings' => [
            'scim_managed_group_ids' => ['group-a', '', 'group-a'],
        ],
    ]);

    expect($provider->getTable())->toBe('sso_providers')
        ->and($provider->owner->is($owner))->toBeTrue()
        ->and($provider->settingsMap())->toBe([
            'scim_managed_group_ids' => ['group-a', '', 'group-a'],
        ])
        ->and($provider->scimManagedGroupIds())->toBe(['group-a', 'group-a'])
        ->and($provider->managesScimGroup('group-a'))->toBeTrue()
        ->and($provider->managesScimGroup('group-b'))->toBeFalse()
        ->and(SsoProvider::query()->enabled()->pluck('id')->all())->toBe([$provider->id])
        ->and($provider->getCasts())->toHaveKeys([
            'client_secret',
            'enabled',
            'enforce_sso',
            'is_default',
            'scim_enabled',
            'validate_issuer',
            'settings',
            'scim_last_used_at',
            'last_used_at',
            'last_login_succeeded_at',
            'last_login_failed_at',
            'last_metadata_refreshed_at',
            'last_metadata_refresh_failed_at',
            'last_validated_at',
            'last_validation_succeeded_at',
            'last_validation_failed_at',
            'secret_rotated_at',
        ]);

    $provider->addScimManagedGroup('group-b');
    $provider->refresh();

    expect($provider->scimManagedGroupIds())->toBe(['group-a', 'group-b']);

    $provider->removeScimManagedGroup('group-a');
    $provider->refresh();

    expect($provider->scimManagedGroupIds())->toBe(['group-b']);

    $emptySettingsProvider = new SsoProvider();
    $emptySettingsProvider->settings = null;
    $emptySettingsProvider->tenant_id = '';

    expect($emptySettingsProvider->settingsMap())->toBe([])
        ->and($emptySettingsProvider->scimManagedGroupIds())->toBe([])
        ->and($emptySettingsProvider->owner()->getResults())->toBeNull();
});
