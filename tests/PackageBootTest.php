<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Configuration\Configuration;
use Cline\SSO\Contracts\PrincipalResolverInterface;
use Cline\SSO\Data\SsoProviderRecord;
use Cline\SSO\Drivers\SsoStrategyResolver;
use Cline\SSO\SsoManager;
use Illuminate\Support\Facades\Route;
use Tests\Fixtures\TestPrincipalResolver;
use Tests\Fixtures\TestStrategy;
use Tests\Fixtures\TestUser;

it('registers the package bindings and routes', function (): void {
    expect(resolve(SsoManager::class))->toBeInstanceOf(SsoManager::class)
        ->and(resolve(PrincipalResolverInterface::class))->toBeInstanceOf(TestPrincipalResolver::class)
        ->and(Route::has('sso.index'))->toBeTrue()
        ->and(Route::has('sso.callback'))->toBeTrue()
        ->and(Route::has('sso.scim.users.index'))->toBeTrue();
});

it('resolves strategies from the configured driver map', function (): void {
    config()->set('sso.drivers', [
        'test' => TestStrategy::class,
    ]);

    $provider = new SsoProviderRecord(
        id: 'provider-1',
        driver: 'test',
        scheme: 'test',
        displayName: 'Test',
        authority: 'https://example.test',
        clientId: 'client-id',
        clientSecret: 'client-secret',
        validIssuer: null,
        validateIssuer: false,
        enabled: true,
        isDefault: false,
        enforceSso: false,
        scimEnabled: false,
        scimTokenHash: null,
        scimLastUsedAt: null,
        lastUsedAt: null,
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
        owner: null,
        settings: [],
    );

    expect(resolve(SsoStrategyResolver::class)->resolve($provider))
        ->toBeInstanceOf(TestStrategy::class);
});

it('reads owner settings from the owner config keys', function (): void {
    config()->set('sso.models.owner', TestUser::class);
    config()->set('sso.foreign_keys.owner.column', 'tenant_id');
    config()->set('sso.foreign_keys.owner.owner_key', 'id');
    config()->set('sso.foreign_keys.owner.type', 'id');

    expect(Configuration::owner()->model())->toBe(TestUser::class)
        ->and(Configuration::owner()->foreignKeyColumn())->toBe('tenant_id')
        ->and(Configuration::owner()->ownerKey())->toBe('id')
        ->and(Configuration::owner()->keyType())->toBe('id');
});
