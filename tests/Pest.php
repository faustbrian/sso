<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Data\ExternalIdentityRecord;
use Cline\SSO\Data\PrincipalReference;
use Cline\SSO\Data\SsoProviderRecord;
use Cline\SSO\ValueObjects\ResolvedIdentity;
use Tests\TestCase;

pest()->extend(TestCase::class)->in(__DIR__);

function makeNullProviderRecord(): SsoProviderRecord
{
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
}

function makeNullExternalIdentityRecord(): ExternalIdentityRecord
{
    return new ExternalIdentityRecord(
        id: 'identity-1',
        emailSnapshot: 'user@example.test',
        issuer: 'https://issuer.example.test',
        linkedPrincipal: new PrincipalReference('users', '42'),
        providerId: 'provider-1',
        subject: 'subject-1',
    );
}

function makeNullResolvedIdentity(): ResolvedIdentity
{
    return new ResolvedIdentity(
        attributes: [],
        email: 'user@example.test',
        issuer: 'https://issuer.example.test',
        subject: 'subject-1',
    );
}
