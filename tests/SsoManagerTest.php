<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Contracts\ExternalIdentityRepositoryInterface;
use Cline\SSO\Contracts\ProviderRepositoryInterface;
use Cline\SSO\Contracts\SsoStrategy;
use Cline\SSO\Data\ExternalIdentityRecord;
use Cline\SSO\Data\OwnerReference;
use Cline\SSO\Data\PrincipalReference;
use Cline\SSO\Data\ProviderSearchCriteria;
use Cline\SSO\Data\SsoProviderRecord;
use Cline\SSO\Drivers\SsoStrategyResolver;
use Cline\SSO\Enums\BooleanFilter;
use Cline\SSO\Models\ExternalIdentity;
use Cline\SSO\Models\SsoProvider;
use Cline\SSO\SsoManager;
use Cline\SSO\ValueObjects\ResolvedIdentity;
use Illuminate\Http\Request;
use Tests\Fixtures\TestUser;

it('finds and deletes external identities by linked subject', function (): void {
    $provider = createProviderRecord();
    $user = TestUser::query()->create([
        'email' => 'linked-subject@example.test',
        'name' => 'Linked Subject',
    ]);

    $record = resolve(SsoManager::class)->saveExternalIdentity(
        new ExternalIdentityRecord(
            id: null,
            emailSnapshot: $user->email,
            issuer: 'scim:'.$provider->scheme,
            linkedPrincipal: new PrincipalReference($user->getMorphClass(), (string) $user->id),
            providerId: $provider->id,
            subject: 'external-user-1',
        ),
    );

    expect(resolve(SsoManager::class)->findExternalIdentityByLinkedPrincipal(
        $provider->id,
        'scim:'.$provider->scheme,
        new PrincipalReference($user->getMorphClass(), (string) $user->id),
    )?->id)->toBe($record->id);

    resolve(SsoManager::class)->deleteExternalIdentityByLinkedPrincipal(
        $provider->id,
        'scim:'.$provider->scheme,
        new PrincipalReference($user->getMorphClass(), (string) $user->id),
    );

    expect(ExternalIdentity::query()->count())->toBe(0);
});

it('lists external identities for a provider and issuer', function (): void {
    $provider = createProviderRecord();
    $firstUser = TestUser::query()->create([
        'email' => 'first@example.test',
        'name' => 'First',
    ]);
    $secondUser = TestUser::query()->create([
        'email' => 'second@example.test',
        'name' => 'Second',
    ]);

    resolve(SsoManager::class)->saveExternalIdentity(
        new ExternalIdentityRecord(
            id: null,
            emailSnapshot: $firstUser->email,
            issuer: 'scim:'.$provider->scheme,
            linkedPrincipal: new PrincipalReference($firstUser->getMorphClass(), (string) $firstUser->id),
            providerId: $provider->id,
            subject: 'external-first',
        ),
    );
    resolve(SsoManager::class)->saveExternalIdentity(
        new ExternalIdentityRecord(
            id: null,
            emailSnapshot: $secondUser->email,
            issuer: 'scim:'.$provider->scheme,
            linkedPrincipal: new PrincipalReference($secondUser->getMorphClass(), (string) $secondUser->id),
            providerId: $provider->id,
            subject: 'external-second',
        ),
    );
    resolve(SsoManager::class)->saveExternalIdentity(
        new ExternalIdentityRecord(
            id: null,
            emailSnapshot: $secondUser->email,
            issuer: 'oidc:'.$provider->scheme,
            linkedPrincipal: new PrincipalReference($secondUser->getMorphClass(), (string) $secondUser->id),
            providerId: $provider->id,
            subject: 'external-oidc',
        ),
    );

    $records = resolve(SsoManager::class)->externalIdentitiesForProvider(
        $provider->id,
        'scim:'.$provider->scheme,
    );

    expect($records)->toHaveCount(2)
        ->and(array_column($records, 'subject'))->toBe(['external-first', 'external-second']);
});

it('covers the manager delegation surface', function (): void {
    $provider = new SsoProviderRecord(
        id: 'provider-1',
        driver: 'test',
        scheme: 'azure-acme',
        displayName: 'Acme Azure',
        authority: 'https://example.test',
        clientId: 'client-id',
        clientSecret: 'client-secret',
        validIssuer: 'https://issuer.example.test',
        validateIssuer: true,
        enabled: true,
        isDefault: false,
        enforceSso: false,
        scimEnabled: true,
        scimTokenHash: 'hashed-token',
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
        settings: ['foo' => 'bar'],
    );

    $identity = new ExternalIdentityRecord(
        id: 'identity-1',
        emailSnapshot: 'person@example.test',
        issuer: 'https://issuer.example.test',
        linkedPrincipal: new PrincipalReference('principal', '42'),
        providerId: $provider->id,
        subject: 'subject-1',
    );

    $strategy = new class() implements SsoStrategy
    {
        public function buildAuthorizationUrl(
            SsoProviderRecord $provider,
            Request $request,
            string $state,
            string $nonce,
        ): string {
            return 'https://example.test/authorize';
        }

        public function resolveIdentity(
            SsoProviderRecord $provider,
            Request $request,
            string $nonce,
        ): ResolvedIdentity {
            return new ResolvedIdentity(
                attributes: [],
                email: 'person@example.test',
                issuer: 'https://issuer.example.test',
                subject: 'subject-1',
            );
        }

        public function validateConfiguration(SsoProviderRecord $provider): array
        {
            return ['validated' => true];
        }

        public function importConfiguration(SsoProviderRecord $provider): array
        {
            return ['authority' => $provider->authority];
        }

        public function refreshMetadata(SsoProviderRecord $provider): array
        {
            return ['refreshed' => true];
        }
    };

    $providerRepository = new class($provider) implements ProviderRepositoryInterface
    {
        public array $criteria = [];

        public array $createdAttributes = [];

        public array $updatedAttributes = [];

        public array $deletedIds = [];

        public function __construct(
            private readonly SsoProviderRecord $provider,
        ) {}

        public function all(ProviderSearchCriteria $criteria): array
        {
            $this->criteria[] = $criteria;

            return [$this->provider];
        }

        public function findById(string $providerId): ?SsoProviderRecord
        {
            return $providerId === $this->provider->id ? $this->provider : null;
        }

        public function findByScheme(string $scheme, bool $enabledOnly = false): ?SsoProviderRecord
        {
            if ($scheme !== $this->provider->scheme) {
                return null;
            }

            if ($enabledOnly && !$this->provider->enabled) {
                return null;
            }

            return $this->provider;
        }

        public function findByScimTokenHash(string $tokenHash): ?SsoProviderRecord
        {
            return $tokenHash === $this->provider->scimTokenHash ? $this->provider : null;
        }

        public function create(array $attributes): SsoProviderRecord
        {
            $this->createdAttributes = $attributes;

            return $this->provider;
        }

        public function update(string $providerId, array $attributes): ?SsoProviderRecord
        {
            $this->updatedAttributes[$providerId] = $attributes;

            return $providerId === $this->provider->id ? $this->provider : null;
        }

        public function delete(string $providerId): bool
        {
            $this->deletedIds[] = $providerId;

            return $providerId === $this->provider->id;
        }
    };

    $identityRepository = new class($identity) implements ExternalIdentityRepositoryInterface
    {
        public array $saved = [];

        public array $deleted = [];

        public function __construct(
            private readonly ExternalIdentityRecord $identity,
        ) {}

        public function find(string $providerId, string $issuer, string $subject): ?ExternalIdentityRecord
        {
            if (
                $providerId === $this->identity->providerId
                && $issuer === $this->identity->issuer
                && $subject === $this->identity->subject
            ) {
                return $this->identity;
            }

            return null;
        }

        public function save(ExternalIdentityRecord $record): ExternalIdentityRecord
        {
            $this->saved[] = $record;

            return $record;
        }

        public function findByLinkedPrincipal(
            string $providerId,
            string $issuer,
            PrincipalReference $principal,
        ): ?ExternalIdentityRecord {
            if (
                $providerId === $this->identity->providerId
                && $issuer === $this->identity->issuer
                && $principal->type === $this->identity->linkedPrincipal->type
                && $principal->key === $this->identity->linkedPrincipal->key
            ) {
                return $this->identity;
            }

            return null;
        }

        public function allForProvider(string $providerId, ?string $issuer = null): array
        {
            if ($providerId !== $this->identity->providerId) {
                return [];
            }

            if ($issuer !== null && $issuer !== $this->identity->issuer) {
                return [];
            }

            return [$this->identity];
        }

        public function deleteByLinkedPrincipal(
            string $providerId,
            string $issuer,
            PrincipalReference $principal,
        ): void {
            $this->deleted[] = [$providerId, $issuer, $principal->type, $principal->key];
        }
    };

    $manager = new SsoManager(
        providers: $providerRepository,
        externalIdentities: $identityRepository,
        resolver: new SsoStrategyResolver(['test' => $strategy]),
    );

    $defaultProviders = $manager->providers();
    $searchedProviders = $manager->searchProviders(
        new ProviderSearchCriteria(
            enabled: BooleanFilter::True,
            owner: new OwnerReference('owner', 'tenant-1'),
        ),
    );

    expect($defaultProviders)->toBe([$provider])
        ->and($providerRepository->criteria[0]->enabled)->toBe(BooleanFilter::True)
        ->and($searchedProviders)->toBe([$provider])
        ->and($manager->findProviderById('provider-1'))->toBe($provider)
        ->and($manager->findProviderById('missing'))->toBeNull()
        ->and($manager->findProviderByScheme('azure-acme', true))->toBe($provider)
        ->and($manager->findProviderByScheme('missing'))->toBeNull()
        ->and($manager->findProviderByScimTokenHash('hashed-token'))->toBe($provider)
        ->and($manager->findProviderByScimTokenHash('missing'))->toBeNull()
        ->and($manager->createProvider(['scheme' => 'azure-acme']))->toBe($provider)
        ->and($providerRepository->createdAttributes)->toBe(['scheme' => 'azure-acme'])
        ->and($manager->updateProvider('provider-1', ['enabled' => false]))->toBe($provider)
        ->and($manager->updateProvider('missing', ['enabled' => false]))->toBeNull()
        ->and($manager->deleteProvider('provider-1'))->toBeTrue()
        ->and($manager->deleteProvider('missing'))->toBeFalse()
        ->and($manager->findExternalIdentity($provider->id, $identity->issuer, $identity->subject))->toBe($identity)
        ->and($manager->findExternalIdentity('missing', $identity->issuer, $identity->subject))->toBeNull()
        ->and($manager->saveExternalIdentity($identity))->toBe($identity)
        ->and($identityRepository->saved)->toHaveCount(1)
        ->and($manager->findExternalIdentityByLinkedPrincipal(
            $provider->id,
            $identity->issuer,
            $identity->linkedPrincipal,
        ))->toBe($identity)
        ->and($manager->findExternalIdentityByLinkedPrincipal(
            $provider->id,
            'missing',
            $identity->linkedPrincipal,
        ))->toBeNull()
        ->and($manager->externalIdentitiesForProvider($provider->id, $identity->issuer))->toBe([$identity])
        ->and($manager->externalIdentitiesForProvider('missing'))->toBe([])
        ->and($manager->validate($provider))->toBe(['validated' => true])
        ->and($manager->import($provider))->toBe(['authority' => $provider->authority])
        ->and($manager->refreshMetadata($provider))->toBe(['refreshed' => true]);

    $manager->deleteExternalIdentityByLinkedPrincipal(
        $provider->id,
        $identity->issuer,
        $identity->linkedPrincipal,
    );

    expect($identityRepository->deleted)->toBe([
        [$provider->id, $identity->issuer, $identity->linkedPrincipal->type, $identity->linkedPrincipal->key],
    ]);
});

function createProviderRecord(): SsoProvider
{
    return SsoProvider::query()->create([
        'tenant_id' => 1,
        'driver' => 'oidc',
        'scheme' => 'azure-acme',
        'display_name' => 'Acme Azure AD',
        'authority' => 'https://login.example.test/acme/v2.0',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'enabled' => true,
        'validate_issuer' => false,
    ]);
}
