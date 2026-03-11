<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Carbon\CarbonImmutable;
use Cline\SSO\Models\ExternalIdentity;
use Cline\SSO\Models\SsoProvider;
use Illuminate\Support\Facades\Http;
use Tests\Fixtures\TestAuditSink;
use Tests\Fixtures\TestPrincipalResolver;
use Tests\Fixtures\TestUser;

it('renders an html chooser for enabled providers', function (): void {
    createOidcProvider([
        'id' => 'provider-index-enabled',
        'driver' => 'oidc',
        'scheme' => 'azure-index',
        'display_name' => 'Acme Azure AD',
        'authority' => 'https://login.example.test/acme/v2.0',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'valid_issuer' => 'https://login.example.test/acme/v2.0',
        'validate_issuer' => true,
        'enabled' => true,
    ]);

    createOidcProvider([
        'id' => 'provider-index-disabled',
        'driver' => 'oidc',
        'scheme' => 'azure-disabled',
        'display_name' => 'Disabled Azure AD',
        'authority' => 'https://login.example.test/acme/v2.0',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'valid_issuer' => 'https://login.example.test/acme/v2.0',
        'validate_issuer' => true,
        'enabled' => false,
    ]);

    $this->get('/sso')
        ->assertSuccessful()
        ->assertSee('Single Sign-On')
        ->assertSee('Acme Azure AD')
        ->assertDontSee('Disabled Azure AD');
});

it('logs in a user with oidc callback flow', function (): void {
    [$privateKey, $publicJwk] = generateOidcKeys();

    $provider = createOidcProvider([
        'id' => 'provider-1',
        'driver' => 'oidc',
        'scheme' => 'azure-acme',
        'display_name' => 'Acme Azure AD',
        'authority' => 'https://login.example.test/acme/v2.0',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'valid_issuer' => 'https://login.example.test/acme/v2.0',
        'validate_issuer' => true,
        'enabled' => true,
    ]);

    $user = TestUser::query()->create([
        'email' => 'first-login@example.test',
        'name' => 'First Login',
        'password' => 'secret',
    ]);

    $this->withSession([
        'sso.'.$provider->scheme => [
            'state' => 'test-state',
            'nonce' => 'test-nonce',
        ],
    ]);

    Http::fake([
        'https://login.example.test/acme/v2.0/.well-known/openid-configuration' => Http::response([
            'authorization_endpoint' => 'https://login.example.test/oauth2/v2.0/authorize',
            'token_endpoint' => 'https://login.example.test/oauth2/v2.0/token',
            'jwks_uri' => 'https://login.example.test/discovery/v2.0/keys',
            'issuer' => $provider->valid_issuer,
        ]),
        'https://login.example.test/oauth2/v2.0/token' => Http::response([
            'access_token' => 'access-token',
            'id_token' => createIdToken(
                privateKey: $privateKey,
                issuer: $provider->valid_issuer,
                audience: $provider->client_id,
                subject: 'entra-subject-2',
                email: $user->email,
                nonce: 'test-nonce',
            ),
            'token_type' => 'Bearer',
            'expires_in' => 3_600,
        ]),
        'https://login.example.test/discovery/v2.0/keys' => Http::response([
            'keys' => [$publicJwk],
        ]),
    ]);

    $this->get('/sso/'.$provider->scheme.'/callback?code=auth-code&state=test-state')
        ->assertRedirect('/');

    $this->assertAuthenticatedAs($user);

    expect(ExternalIdentity::query()
        ->where('sso_provider_id', $provider->id)
        ->where('user_id', $user->id)
        ->where('subject', 'entra-subject-2')
        ->exists())->toBeTrue()
        ->and(TestAuditSink::$events)->toHaveCount(1)
        ->and(TestAuditSink::$events[0]['event'])->toBe('provider_login_succeeded');
});

it('rejects the callback when the sso state is invalid', function (): void {
    $provider = createOidcProvider([
        'id' => 'provider-invalid-state',
        'driver' => 'oidc',
        'scheme' => 'azure-acme',
        'display_name' => 'Acme Azure AD',
        'authority' => 'https://login.example.test/acme/v2.0',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'valid_issuer' => 'https://login.example.test/acme/v2.0',
        'validate_issuer' => true,
        'enabled' => true,
    ]);

    $this->withSession([
        'sso.'.$provider->scheme => [
            'state' => 'different-state',
            'nonce' => 'test-nonce',
        ],
    ]);

    $this->followingRedirects()->get('/sso/'.$provider->scheme.'/callback?code=auth-code&state=test-state')
        ->assertSee('Single Sign-On')
        ->assertSee('The SSO state is invalid or has expired.');

    expect($provider->fresh()->last_login_failed_at)->not->toBeNull()
        ->and(TestAuditSink::$events)->toHaveCount(1)
        ->and(TestAuditSink::$events[0]['event'])->toBe('provider_login_failed');
});

it('links an existing user by email on first oidc login', function (): void {
    [$privateKey, $publicJwk] = generateOidcKeys();

    $provider = createOidcProvider([
        'id' => 'provider-first-link',
        'driver' => 'oidc',
        'scheme' => 'azure-link',
        'display_name' => 'Acme Azure AD',
        'authority' => 'https://login.example.test/acme/v2.0',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'valid_issuer' => 'https://login.example.test/acme/v2.0',
        'validate_issuer' => true,
        'enabled' => true,
    ]);
    $user = TestUser::query()->create([
        'email' => 'first-login@example.test',
        'name' => 'First Login',
        'password' => 'secret',
    ]);

    $this->withSession([
        'sso.'.$provider->scheme => [
            'state' => 'test-state',
            'nonce' => 'test-nonce',
        ],
    ]);

    Http::fake([
        'https://login.example.test/acme/v2.0/.well-known/openid-configuration' => Http::response([
            'authorization_endpoint' => 'https://login.example.test/oauth2/v2.0/authorize',
            'token_endpoint' => 'https://login.example.test/oauth2/v2.0/token',
            'jwks_uri' => 'https://login.example.test/discovery/v2.0/keys',
            'issuer' => $provider->valid_issuer,
        ]),
        'https://login.example.test/oauth2/v2.0/token' => Http::response([
            'access_token' => 'access-token',
            'id_token' => createIdToken(
                privateKey: $privateKey,
                issuer: $provider->valid_issuer,
                audience: $provider->client_id,
                subject: 'entra-subject-link',
                email: $user->email,
                nonce: 'test-nonce',
            ),
            'token_type' => 'Bearer',
            'expires_in' => 3_600,
        ]),
        'https://login.example.test/discovery/v2.0/keys' => Http::response([
            'keys' => [$publicJwk],
        ]),
    ]);

    $this->get('/sso/'.$provider->scheme.'/callback?code=auth-code&state=test-state')
        ->assertRedirect('/');

    expect(ExternalIdentity::query()
        ->where('sso_provider_id', $provider->id)
        ->where('user_id', $user->id)
        ->where('subject', 'entra-subject-link')
        ->exists())->toBeTrue();
});

it('auto provisions a user when the provider allows it', function (): void {
    [$privateKey, $publicJwk] = generateOidcKeys();

    $provider = createOidcProvider([
        'id' => 'provider-provision',
        'driver' => 'oidc',
        'scheme' => 'azure-provision',
        'display_name' => 'Acme Azure AD',
        'authority' => 'https://login.example.test/acme/v2.0',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'valid_issuer' => 'https://login.example.test/acme/v2.0',
        'validate_issuer' => true,
        'enabled' => true,
        'settings' => [
            'provision_mode' => 'auto_create',
        ],
    ]);

    $this->withSession([
        'sso.'.$provider->scheme => [
            'state' => 'test-state',
            'nonce' => 'test-nonce',
        ],
    ]);

    Http::fake([
        'https://login.example.test/acme/v2.0/.well-known/openid-configuration' => Http::response([
            'authorization_endpoint' => 'https://login.example.test/oauth2/v2.0/authorize',
            'token_endpoint' => 'https://login.example.test/oauth2/v2.0/token',
            'jwks_uri' => 'https://login.example.test/discovery/v2.0/keys',
            'issuer' => $provider->valid_issuer,
        ]),
        'https://login.example.test/oauth2/v2.0/token' => Http::response([
            'access_token' => 'access-token',
            'id_token' => createIdToken(
                privateKey: $privateKey,
                issuer: $provider->valid_issuer,
                audience: $provider->client_id,
                subject: 'entra-subject-provision',
                email: 'auto-provision@example.test',
                nonce: 'test-nonce',
            ),
            'token_type' => 'Bearer',
            'expires_in' => 3_600,
        ]),
        'https://login.example.test/discovery/v2.0/keys' => Http::response([
            'keys' => [$publicJwk],
        ]),
    ]);

    $this->get('/sso/'.$provider->scheme.'/callback?code=auth-code&state=test-state')
        ->assertRedirect('/');

    expect(TestUser::query()->where('email', 'auto-provision@example.test')->exists())->toBeTrue();
});

it('rejects first login when the resolver does not allow linking', function (): void {
    [$privateKey, $publicJwk] = generateOidcKeys();
    TestPrincipalResolver::$allowLink = false;

    $provider = createOidcProvider([
        'id' => 'provider-no-link',
        'driver' => 'oidc',
        'scheme' => 'azure-no-link',
        'display_name' => 'Acme Azure AD',
        'authority' => 'https://login.example.test/acme/v2.0',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'valid_issuer' => 'https://login.example.test/acme/v2.0',
        'validate_issuer' => true,
        'enabled' => true,
    ]);
    $user = TestUser::query()->create([
        'email' => 'reject-link@example.test',
        'name' => 'Reject Link',
        'password' => 'secret',
    ]);

    $this->withSession([
        'sso.'.$provider->scheme => [
            'state' => 'test-state',
            'nonce' => 'test-nonce',
        ],
    ]);

    Http::fake([
        'https://login.example.test/acme/v2.0/.well-known/openid-configuration' => Http::response([
            'authorization_endpoint' => 'https://login.example.test/oauth2/v2.0/authorize',
            'token_endpoint' => 'https://login.example.test/oauth2/v2.0/token',
            'jwks_uri' => 'https://login.example.test/discovery/v2.0/keys',
            'issuer' => $provider->valid_issuer,
        ]),
        'https://login.example.test/oauth2/v2.0/token' => Http::response([
            'access_token' => 'access-token',
            'id_token' => createIdToken(
                privateKey: $privateKey,
                issuer: $provider->valid_issuer,
                audience: $provider->client_id,
                subject: 'entra-subject-reject',
                email: $user->email,
                nonce: 'test-nonce',
            ),
            'token_type' => 'Bearer',
            'expires_in' => 3_600,
        ]),
        'https://login.example.test/discovery/v2.0/keys' => Http::response([
            'keys' => [$publicJwk],
        ]),
    ]);

    $this->get('/sso/'.$provider->scheme.'/callback?code=auth-code&state=test-state')
        ->assertRedirect('/sso')
        ->assertSessionHasErrors('sso');

    expect(ExternalIdentity::query()->where('sso_provider_id', $provider->id)->exists())->toBeFalse();
});

it('rejects oidc callback when the resolved principal may not sign in', function (): void {
    [$privateKey, $publicJwk] = generateOidcKeys();
    TestPrincipalResolver::$allowSignIn = false;

    $provider = createOidcProvider([
        'id' => 'provider-no-sign-in',
        'driver' => 'oidc',
        'scheme' => 'azure-no-sign-in',
        'display_name' => 'Acme Azure AD',
        'authority' => 'https://login.example.test/acme/v2.0',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'valid_issuer' => 'https://login.example.test/acme/v2.0',
        'validate_issuer' => true,
        'enabled' => true,
    ]);

    $user = TestUser::query()->create([
        'email' => 'cannot-sign-in@example.test',
        'name' => 'Cannot Sign In',
        'password' => 'secret',
    ]);

    $this->withSession([
        'sso.'.$provider->scheme => [
            'state' => 'test-state',
            'nonce' => 'test-nonce',
        ],
    ]);

    Http::fake([
        'https://login.example.test/acme/v2.0/.well-known/openid-configuration' => Http::response([
            'authorization_endpoint' => 'https://login.example.test/oauth2/v2.0/authorize',
            'token_endpoint' => 'https://login.example.test/oauth2/v2.0/token',
            'jwks_uri' => 'https://login.example.test/discovery/v2.0/keys',
            'issuer' => $provider->valid_issuer,
        ]),
        'https://login.example.test/oauth2/v2.0/token' => Http::response([
            'access_token' => 'access-token',
            'id_token' => createIdToken(
                privateKey: $privateKey,
                issuer: $provider->valid_issuer,
                audience: $provider->client_id,
                subject: 'entra-subject-no-sign-in',
                email: $user->email,
                nonce: 'test-nonce',
            ),
            'token_type' => 'Bearer',
            'expires_in' => 3_600,
        ]),
        'https://login.example.test/discovery/v2.0/keys' => Http::response([
            'keys' => [$publicJwk],
        ]),
    ]);

    $this->get('/sso/'.$provider->scheme.'/callback?code=auth-code&state=test-state')
        ->assertRedirect('/sso')
        ->assertSessionHasErrors('sso');

    $this->assertGuest();

    expect($provider->fresh()->last_login_failed_at)->not->toBeNull()
        ->and(TestAuditSink::$events)->toHaveCount(1)
        ->and(TestAuditSink::$events[0]['event'])->toBe('provider_login_failed');
});

it('refreshes the email snapshot on an existing external identity during oidc login', function (): void {
    [$privateKey, $publicJwk] = generateOidcKeys();

    $provider = createOidcProvider([
        'id' => 'provider-email-snapshot',
        'driver' => 'oidc',
        'scheme' => 'azure-email-snapshot',
        'display_name' => 'Acme Azure AD',
        'authority' => 'https://login.example.test/acme/v2.0',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'valid_issuer' => 'https://login.example.test/acme/v2.0',
        'validate_issuer' => true,
        'enabled' => true,
    ]);

    $user = TestUser::query()->create([
        'email' => 'new-email@example.test',
        'name' => 'Snapshot User',
        'password' => 'secret',
    ]);

    ExternalIdentity::query()->create([
        'user_id' => $user->id,
        'sso_provider_id' => $provider->id,
        'issuer' => $provider->valid_issuer,
        'subject' => 'entra-subject-snapshot',
        'email_snapshot' => 'old-email@example.test',
    ]);

    $this->withSession([
        'sso.'.$provider->scheme => [
            'state' => 'test-state',
            'nonce' => 'test-nonce',
        ],
    ]);

    Http::fake([
        'https://login.example.test/acme/v2.0/.well-known/openid-configuration' => Http::response([
            'authorization_endpoint' => 'https://login.example.test/oauth2/v2.0/authorize',
            'token_endpoint' => 'https://login.example.test/oauth2/v2.0/token',
            'jwks_uri' => 'https://login.example.test/discovery/v2.0/keys',
            'issuer' => $provider->valid_issuer,
        ]),
        'https://login.example.test/oauth2/v2.0/token' => Http::response([
            'access_token' => 'access-token',
            'id_token' => createIdToken(
                privateKey: $privateKey,
                issuer: $provider->valid_issuer,
                audience: $provider->client_id,
                subject: 'entra-subject-snapshot',
                email: $user->email,
                nonce: 'test-nonce',
            ),
            'token_type' => 'Bearer',
            'expires_in' => 3_600,
        ]),
        'https://login.example.test/discovery/v2.0/keys' => Http::response([
            'keys' => [$publicJwk],
        ]),
    ]);

    $this->get('/sso/'.$provider->scheme.'/callback?code=auth-code&state=test-state')
        ->assertRedirect('/');

    expect(ExternalIdentity::query()->where('sso_provider_id', $provider->id)->sole()->email_snapshot)
        ->toBe($user->email);
});

it('redirects to a configured route name after login', function (): void {
    config()->set('sso.login.redirect_route_name', 'dashboard');

    [$privateKey, $publicJwk] = generateOidcKeys();

    $provider = createOidcProvider([
        'id' => 'provider-route-redirect',
        'driver' => 'oidc',
        'scheme' => 'azure-redirect-route',
        'display_name' => 'Acme Azure AD',
        'authority' => 'https://login.example.test/acme/v2.0',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'valid_issuer' => 'https://login.example.test/acme/v2.0',
        'validate_issuer' => true,
        'enabled' => true,
    ]);
    $user = TestUser::query()->create([
        'email' => 'route-redirect@example.test',
        'name' => 'Route Redirect',
        'password' => 'secret',
    ]);

    $this->withSession([
        'sso.'.$provider->scheme => [
            'state' => 'test-state',
            'nonce' => 'test-nonce',
        ],
    ]);

    Http::fake([
        'https://login.example.test/acme/v2.0/.well-known/openid-configuration' => Http::response([
            'authorization_endpoint' => 'https://login.example.test/oauth2/v2.0/authorize',
            'token_endpoint' => 'https://login.example.test/oauth2/v2.0/token',
            'jwks_uri' => 'https://login.example.test/discovery/v2.0/keys',
            'issuer' => $provider->valid_issuer,
        ]),
        'https://login.example.test/oauth2/v2.0/token' => Http::response([
            'access_token' => 'access-token',
            'id_token' => createIdToken(
                privateKey: $privateKey,
                issuer: $provider->valid_issuer,
                audience: $provider->client_id,
                subject: 'entra-subject-route-redirect',
                email: $user->email,
                nonce: 'test-nonce',
            ),
            'token_type' => 'Bearer',
            'expires_in' => 3_600,
        ]),
        'https://login.example.test/discovery/v2.0/keys' => Http::response([
            'keys' => [$publicJwk],
        ]),
    ]);

    $this->get('/sso/'.$provider->scheme.'/callback?code=auth-code&state=test-state')
        ->assertRedirect(route('dashboard', ['locale' => 'en']));
});

function generateOidcKeys(): array
{
    $resource = openssl_pkey_new([
        'private_key_bits' => 2_048,
        'private_key_type' => \OPENSSL_KEYTYPE_RSA,
    ]);

    openssl_pkey_export($resource, $privateKey);

    $details = openssl_pkey_get_details($resource);

    return [$privateKey, [
        'kty' => 'RSA',
        'kid' => 'test-key-id',
        'alg' => 'RS256',
        'use' => 'sig',
        'n' => base64UrlEncode($details['rsa']['n']),
        'e' => base64UrlEncode($details['rsa']['e']),
    ]];
}

function createOidcProvider(array $attributes): SsoProvider
{
    $tenant = TestUser::query()->create([
        'email' => 'org-'.(SsoProvider::query()->count() + 1).'@example.test',
        'name' => 'Tenant',
        'password' => 'secret',
    ]);

    return SsoProvider::query()->create([
        'tenant_id' => $tenant->id,
        ...$attributes,
    ]);
}

function createIdToken(
    string $privateKey,
    string $issuer,
    string|array $audience,
    string $subject,
    string $email,
    string $nonce,
): string {
    $now = CarbonImmutable::now();
    $header = [
        'alg' => 'RS256',
        'kid' => 'test-key-id',
        'typ' => 'JWT',
    ];

    $claims = [
        'iss' => $issuer,
        'sub' => $subject,
        'aud' => array_values((array) $audience),
        'iat' => $now->modify('-1 minute')->getTimestamp(),
        'exp' => $now->modify('+1 hour')->getTimestamp(),
        'nbf' => $now->modify('-1 minute')->getTimestamp(),
        'email' => $email,
        'nonce' => $nonce,
    ];

    if (count($claims['aud']) === 1) {
        $claims['aud'] = $claims['aud'][0];
    }

    $encodedHeader = base64UrlEncode(json_encode($header, \JSON_THROW_ON_ERROR));
    $encodedClaims = base64UrlEncode(json_encode($claims, \JSON_THROW_ON_ERROR));
    $signingInput = $encodedHeader.'.'.$encodedClaims;

    openssl_sign($signingInput, $signature, $privateKey, \OPENSSL_ALGO_SHA256);

    return $signingInput.'.'.base64UrlEncode($signature);
}

function base64UrlEncode(string $value): string
{
    return mb_rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
}
