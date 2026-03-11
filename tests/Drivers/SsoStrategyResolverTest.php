<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Contracts\SsoStrategy;
use Cline\SSO\Data\OwnerReference;
use Cline\SSO\Data\SsoProviderRecord;
use Cline\SSO\Drivers\SsoStrategyResolver;
use Cline\SSO\Exceptions\UnknownSsoDriverException;
use Tests\Fixtures\TestStrategy;

it('throws when resolving an unknown driver', function (): void {
    $resolver = new SsoStrategyResolver([
        'known' => new TestStrategy(),
    ]);

    expect(fn (): SsoStrategy => $resolver->resolve(
        new SsoProviderRecord(
            id: 'provider-1',
            driver: 'missing',
            scheme: 'scheme',
            displayName: 'Display',
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
            owner: new OwnerReference('owner', 'tenant-1'),
            settings: [],
        ),
    ))->toThrow(UnknownSsoDriverException::class);
});
