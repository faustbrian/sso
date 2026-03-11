<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Drivers\Oidc;

use Carbon\CarbonImmutable;
use Cline\JWT\Configuration as JwtConfiguration;
use Cline\JWT\Contracts\SignerInterface;
use Cline\JWT\Contracts\UnencryptedTokenInterface;
use Cline\JWT\Signer\Key\InMemory;
use Cline\JWT\Signer\Rsa\Sha256;
use Cline\JWT\Signer\Rsa\Sha384;
use Cline\JWT\Signer\Rsa\Sha512;
use Cline\JWT\Token\RegisteredClaims;
use Cline\JWT\Validation\Constraint\SignedWith;
use Cline\SSO\Configuration\Configuration as PackageConfiguration;
use Cline\SSO\Contracts\SsoStrategy;
use Cline\SSO\Data\SsoProviderRecord;
use Cline\SSO\Exceptions\ExpiredOidcTokenException;
use Cline\SSO\Exceptions\InvalidAuthorizedPartyException;
use Cline\SSO\Exceptions\InvalidJwksResponseException;
use Cline\SSO\Exceptions\InvalidOidcAudienceException;
use Cline\SSO\Exceptions\InvalidOidcDiscoveryIssuerException;
use Cline\SSO\Exceptions\InvalidOidcDiscoveryResponseException;
use Cline\SSO\Exceptions\InvalidOidcIssuerException;
use Cline\SSO\Exceptions\InvalidOidcIssueTimeException;
use Cline\SSO\Exceptions\InvalidOidcNonceException;
use Cline\SSO\Exceptions\InvalidOidcTokenHeaderException;
use Cline\SSO\Exceptions\InvalidOidcTokenResponseException;
use Cline\SSO\Exceptions\InvalidOidcTokenStructureException;
use Cline\SSO\Exceptions\InvalidOidcTokenTypeException;
use Cline\SSO\Exceptions\MissingExpectedOidcIssuerException;
use Cline\SSO\Exceptions\MissingIdTokenException;
use Cline\SSO\Exceptions\MissingOidcDiscoveryKeyException;
use Cline\SSO\Exceptions\MissingOidcKeyIdentifierException;
use Cline\SSO\Exceptions\MissingOidcSigningAlgorithmException;
use Cline\SSO\Exceptions\MissingOidcSigningKeysException;
use Cline\SSO\Exceptions\MissingRequiredOidcClaimsException;
use Cline\SSO\Exceptions\OidcTokenNotYetValidException;
use Cline\SSO\Exceptions\UnresolvedOidcSigningKeyException;
use Cline\SSO\Exceptions\UnsupportedOidcAlgorithmException;
use Cline\SSO\ValueObjects\ResolvedIdentity;
use DateTimeImmutable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use phpseclib3\Crypt\PublicKeyLoader;

use const JSON_THROW_ON_ERROR;

use function base64_decode;
use function collect;
use function count;
use function explode;
use function http_build_query;
use function in_array;
use function is_array;
use function is_bool;
use function is_string;
use function json_decode;
use function json_encode;
use function mb_rtrim;
use function mb_strlen;
use function mb_strtoupper;
use function now;
use function route;
use function sha1;
use function sprintf;
use function str_repeat;
use function strtr;

/**
 * Implements the OpenID Connect authorization-code flow for provider records.
 *
 * This strategy discovers provider metadata, exchanges the callback code for
 * tokens, validates ID-token signatures against remote JWK sets, and converts
 * the resulting claims into the package's normalized identity object. It is
 * the protocol boundary between a stored OIDC-capable provider record and the
 * package's protocol-agnostic login lifecycle.
 *
 * The implementation aggressively validates remote metadata and token claims so
 * higher layers only ever receive identities that have already satisfied the
 * issuer, audience, nonce, timing, and signature guarantees required for a
 * trustworthy login.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class OidcStrategy implements SsoStrategy
{
    /**
     * Build the provider authorization URL for an interactive login attempt.
     *
     * Discovery metadata supplies the authorization endpoint while state and
     * nonce bind the callback to the originating browser session. The resulting
     * URL is safe to redirect to directly because all protocol parameters are
     * derived from the persisted provider record and current request context.
     */
    public function buildAuthorizationUrl(SsoProviderRecord $provider, Request $request, string $state, string $nonce): string
    {
        $configuration = $this->discover($provider);

        return $configuration['authorization_endpoint'].'?'.http_build_query([
            'client_id' => $provider->clientId,
            'redirect_uri' => $this->callbackUrl($provider),
            'response_type' => 'code',
            'scope' => 'openid profile email',
            'state' => $state,
            'nonce' => $nonce,
        ]);
    }

    /**
     * Exchange the callback code and validate the returned ID token.
     *
     * The resolved identity is only returned after signature, nonce, audience,
     * issuer, and time-based claim checks all succeed. Any missing code, token,
     * or required claim is treated as a hard failure rather than a partially
     * trusted identity.
     */
    public function resolveIdentity(SsoProviderRecord $provider, Request $request, string $nonce): ResolvedIdentity
    {
        $oidcConfiguration = $this->discover($provider);
        $tokens = $this->exchangeCode($provider, $request, $oidcConfiguration['token_endpoint']);
        $idToken = $tokens['id_token'] ?? null;

        if (!is_string($idToken) || $idToken === '') {
            throw MissingIdTokenException::create();
        }

        return $this->validateIdToken(
            provider: $provider,
            idToken: $idToken,
            jwksUri: $oidcConfiguration['jwks_uri'],
            nonce: $nonce,
            discoveredIssuer: $oidcConfiguration['issuer'] ?? null,
        );
    }

    /**
     * Validate that the provider exposes the minimum OIDC metadata required to
     * complete login and verify tokens.
     *
     * Administrative tooling uses this to confirm that discovery metadata and
     * signing keys are present before users encounter runtime failures.
     *
     * @return array<string, null|scalar>
     */
    public function validateConfiguration(SsoProviderRecord $provider): array
    {
        $configuration = $this->discover($provider);
        $jwksUri = $configuration['jwks_uri'];

        /** @var array<int, array<string, mixed>> $jwks */
        $jwks = Cache::remember(
            'sso:oidc:jwks:'.sha1($jwksUri),
            now()->addSeconds(PackageConfiguration::cache()->jwksTtl()),
            function () use ($jwksUri): array {
                $jwks = Http::timeout(10)->get($jwksUri)->throw()->json('keys');

                if (!is_array($jwks)) {
                    throw InvalidJwksResponseException::create();
                }

                /** @var array<int, array<string, mixed>> $jwks */
                return $jwks;
            },
        );

        $signingKeys = collect($jwks)
            ->filter(function (array $candidate): bool {
                if (($candidate['kty'] ?? null) !== 'RSA') {
                    return false;
                }

                return !isset($candidate['use']) || $candidate['use'] === 'sig';
            })
            ->count();

        if ($signingKeys === 0) {
            throw MissingOidcSigningKeysException::create();
        }

        if ($provider->validateIssuer) {
            $expectedIssuer = $provider->validIssuer ?: ($configuration['issuer'] ?? null);

            if (!is_string($expectedIssuer) || $expectedIssuer === '') {
                throw MissingExpectedOidcIssuerException::create();
            }
        }

        return [
            'authorization_endpoint' => $configuration['authorization_endpoint'],
            'issuer' => $configuration['issuer'] ?? $provider->validIssuer,
            'jwks_uri' => $jwksUri,
            'signing_keys' => $signingKeys,
            'token_endpoint' => $configuration['token_endpoint'],
        ];
    }

    /**
     * Import canonical authority and issuer values from discovery metadata.
     *
     * The imported values are suitable for persistence on the provider record
     * so future validations can rely on normalized authority and issuer data.
     *
     * @return array{
     *     authority: string,
     *     valid_issuer: null|string
     * }
     */
    public function importConfiguration(SsoProviderRecord $provider): array
    {
        $configuration = $this->discover($provider);

        return [
            'authority' => mb_rtrim($provider->authority, '/'),
            'valid_issuer' => is_string($configuration['issuer'] ?? null)
                ? $configuration['issuer']
                : null,
        ];
    }

    /**
     * Clear cached discovery and signing-key metadata before revalidating.
     *
     * This forces the next validation pass to observe upstream metadata changes
     * such as endpoint moves or key rotation.
     *
     * @return array<string, null|scalar>
     */
    public function refreshMetadata(SsoProviderRecord $provider): array
    {
        Cache::forget($this->discoveryCacheKey($provider->authority));

        $configuration = $this->discover($provider);

        Cache::forget($this->jwksCacheKey($configuration['jwks_uri']));

        return $this->validateConfiguration($provider);
    }

    /**
     * Resolve and cache the provider's discovery document.
     *
     * The returned payload is guaranteed to contain the endpoints required by
     * the rest of the OIDC flow.
     *
     * @return array{authorization_endpoint: string, issuer?: string, jwks_uri: string, token_endpoint: string}
     */
    private function discover(SsoProviderRecord $provider): array
    {
        $authority = mb_rtrim($provider->authority, '/');

        $configuration = Cache::remember(
            'sso:oidc:discovery:'.sha1($authority),
            now()->addSeconds(PackageConfiguration::cache()->discoveryTtl()),
            function () use ($authority): array {
                $configuration = Http::timeout(10)
                    ->get($authority.'/.well-known/openid-configuration')
                    ->throw()
                    ->json();

                if (!is_array($configuration)) {
                    throw InvalidOidcDiscoveryResponseException::create();
                }

                foreach (['authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $requiredKey) {
                    if (!is_string($configuration[$requiredKey] ?? null) || $configuration[$requiredKey] === '') {
                        throw MissingOidcDiscoveryKeyException::forKey($requiredKey);
                    }
                }

                if (isset($configuration['issuer']) && !is_string($configuration['issuer'])) {
                    throw InvalidOidcDiscoveryIssuerException::create();
                }

                /** @var array{authorization_endpoint: string, issuer?: string, jwks_uri: string, token_endpoint: string} $configuration */
                return $configuration;
            },
        );

        if (!is_array($configuration)) {
            throw InvalidOidcDiscoveryResponseException::create();
        }

        /** @var array{authorization_endpoint: string, issuer?: string, jwks_uri: string, token_endpoint: string} $configuration */
        return $configuration;
    }

    /**
     * Exchange the authorization code for token response data.
     *
     * @return array<string, mixed>
     */
    private function exchangeCode(SsoProviderRecord $provider, Request $request, string $tokenEndpoint): array
    {
        $tokens = Http::asForm()
            ->post($tokenEndpoint, [
                'grant_type' => 'authorization_code',
                'code' => $request->string('code')->toString(),
                'redirect_uri' => $this->callbackUrl($provider),
                'client_id' => $provider->clientId,
                'client_secret' => $provider->clientSecret,
            ])
            ->throw()
            ->json();

        if (!is_array($tokens)) {
            throw InvalidOidcTokenResponseException::create();
        }

        /** @var array<string, mixed> $tokens */
        return $tokens;
    }

    /**
     * Parse and validate the ID token before converting it into package form.
     *
     * This method enforces signature, issuer, audience, nonce, and temporal
     * constraints so callers never receive a partially verified identity.
     */
    private function validateIdToken(
        SsoProviderRecord $provider,
        string $idToken,
        string $jwksUri,
        string $nonce,
        ?string $discoveredIssuer,
    ): ResolvedIdentity {
        $header = $this->decodeJwtHeader($idToken);
        $algorithm = $header['alg'] ?? null;
        $tokenType = $header['typ'] ?? null;

        if (!is_string($algorithm) || $algorithm === '') {
            throw MissingOidcSigningAlgorithmException::create();
        }

        if (is_string($tokenType) && mb_strtoupper($tokenType) !== 'JWT') {
            throw InvalidOidcTokenTypeException::create();
        }

        /** @var non-empty-string $verificationKey */
        $verificationKey = $this->resolveVerificationKey($header, $jwksUri);

        /** @var non-empty-string $nonEmptyIdToken */
        $nonEmptyIdToken = $idToken;

        $configuration = JwtConfiguration::forAsymmetricSigner(
            $this->resolveSigner($algorithm),
            InMemory::plainText('unused'),
            InMemory::plainText($verificationKey),
        );

        $token = $configuration->parser()->parse($nonEmptyIdToken);

        if (!$token instanceof UnencryptedTokenInterface) {
            throw InvalidOidcTokenStructureException::create();
        }

        $configuration->validator()->assert($token, new SignedWith(
            $configuration->signer(),
            $configuration->verificationKey(),
        ));

        $claims = $token->claims();
        $issuer = $claims->get(RegisteredClaims::ISSUER);
        $subject = $claims->get(RegisteredClaims::SUBJECT);
        $audience = $claims->get(RegisteredClaims::AUDIENCE);
        $expiresAt = $claims->get(RegisteredClaims::EXPIRATION_TIME);
        $issuedAt = $claims->get(RegisteredClaims::ISSUED_AT);
        $notBefore = $claims->get(RegisteredClaims::NOT_BEFORE);
        $tokenNonce = $claims->get('nonce');

        if (!is_string($issuer) || !is_string($subject) || !is_string($tokenNonce)) {
            throw MissingRequiredOidcClaimsException::create();
        }

        if ($tokenNonce !== $nonce) {
            throw InvalidOidcNonceException::create();
        }

        if (!in_array($provider->clientId, (array) $audience, true)) {
            throw InvalidOidcAudienceException::create();
        }

        if (count((array) $audience) > 1) {
            $authorizedParty = $claims->get('azp');

            if (!is_string($authorizedParty) || $authorizedParty !== $provider->clientId) {
                throw InvalidAuthorizedPartyException::create();
            }
        }

        $now = CarbonImmutable::now();
        $leeway = 60;

        if (!$expiresAt instanceof DateTimeImmutable || $expiresAt <= $now->modify(sprintf('-%d seconds', $leeway))) {
            throw ExpiredOidcTokenException::create();
        }

        if (!$issuedAt instanceof DateTimeImmutable || $issuedAt > $now->modify(sprintf('+%d seconds', $leeway))) {
            throw InvalidOidcIssueTimeException::create();
        }

        if ($notBefore instanceof DateTimeImmutable && $notBefore > $now->modify(sprintf('+%d seconds', $leeway))) {
            throw OidcTokenNotYetValidException::create();
        }

        if ($provider->validateIssuer) {
            $expectedIssuer = $provider->validIssuer ?: $discoveredIssuer;

            if (!is_string($expectedIssuer) || $expectedIssuer === '' || $issuer !== $expectedIssuer) {
                throw InvalidOidcIssuerException::create();
            }
        }

        $email = $claims->has('email')
            ? $claims->get('email')
            : ($claims->has('preferred_username') ? $claims->get('preferred_username') : null);
        $emailVerified = $claims->has('email_verified') ? $claims->get('email_verified') : null;
        $groups = $claims->has('groups') ? $claims->get('groups') : [];
        $name = $claims->has('name') ? $claims->get('name') : null;
        $roles = $claims->has('roles') ? $claims->get('roles') : [];

        return new ResolvedIdentity(
            attributes: [
                'email_verified' => is_bool($emailVerified) ? $emailVerified : null,
                'groups' => is_array($groups) ? $groups : [],
                'name' => is_string($name) ? $name : null,
                'roles' => is_array($roles) ? $roles : [],
            ],
            email: is_string($email) ? Str::lower($email) : null,
            issuer: $issuer,
            subject: $subject,
        );
    }

    /**
     * @param array<string, mixed> $header
     */
    private function resolveVerificationKey(array $header, string $jwksUri): string
    {
        $keyId = $header['kid'] ?? null;
        $algorithm = $header['alg'] ?? null;

        if (!is_string($keyId) || $keyId === '') {
            throw MissingOidcKeyIdentifierException::create();
        }

        if (!is_string($algorithm) || $algorithm === '') {
            throw MissingOidcSigningAlgorithmException::create();
        }

        /** @var array<int, array<string, mixed>> $jwks */
        $jwks = Cache::remember(
            'sso:oidc:jwks:'.sha1($jwksUri),
            now()->addSeconds(PackageConfiguration::cache()->jwksTtl()),
            function () use ($jwksUri): array {
                $jwks = Http::timeout(10)->get($jwksUri)->throw()->json('keys');

                if (!is_array($jwks)) {
                    throw InvalidJwksResponseException::create();
                }

                /** @var array<int, array<string, mixed>> $jwks */
                return $jwks;
            },
        );

        $jwk = collect($jwks)->first(function (array $candidate) use ($algorithm, $keyId): bool {
            if (($candidate['kid'] ?? null) !== $keyId) {
                return false;
            }

            if (($candidate['kty'] ?? null) !== 'RSA') {
                return false;
            }

            if (isset($candidate['use']) && $candidate['use'] !== 'sig') {
                return false;
            }

            return !isset($candidate['alg']) || $candidate['alg'] === $algorithm;
        });

        if (!is_array($jwk)) {
            throw UnresolvedOidcSigningKeyException::create();
        }

        $publicKey = PublicKeyLoader::loadPublicKey(json_encode($jwk, JSON_THROW_ON_ERROR))
            ->toString('PKCS8');

        if (!is_string($publicKey) || $publicKey === '') {
            throw UnresolvedOidcSigningKeyException::create();
        }

        return $publicKey;
    }

    /**
     * @return array<string, mixed>
     */
    private function decodeJwtHeader(string $idToken): array
    {
        $segments = explode('.', $idToken);

        if (count($segments) < 2) {
            throw InvalidOidcTokenStructureException::create();
        }

        $decoded = base64_decode($this->normalizeBase64UrlSegment($segments[0]), true);

        if (!is_string($decoded) || $decoded === '') {
            throw InvalidOidcTokenHeaderException::create();
        }

        /** @var mixed $header */
        $header = json_decode($decoded, true, 512, JSON_THROW_ON_ERROR);

        if (!is_array($header)) {
            throw InvalidOidcTokenHeaderException::create();
        }

        /** @var array<string, mixed> $header */
        return $header;
    }

    private function normalizeBase64UrlSegment(string $segment): string
    {
        $normalized = strtr($segment, '-_', '+/');
        $paddingLength = (4 - (mb_strlen($normalized) % 4)) % 4;

        return $normalized.str_repeat('=', $paddingLength);
    }

    private function resolveSigner(string $algorithm): SignerInterface
    {
        return match ($algorithm) {
            'RS256' => new Sha256(),
            'RS384' => new Sha384(),
            'RS512' => new Sha512(),
            default => throw UnsupportedOidcAlgorithmException::forAlgorithm($algorithm),
        };
    }

    private function discoveryCacheKey(string $authority): string
    {
        return 'sso:oidc:discovery:'.sha1(mb_rtrim($authority, '/'));
    }

    private function jwksCacheKey(string $jwksUri): string
    {
        return 'sso:oidc:jwks:'.sha1($jwksUri);
    }

    private function callbackUrl(SsoProviderRecord $provider): string
    {
        $routeName = PackageConfiguration::routes()->callbackName();

        return route($routeName, [
            'scheme' => $provider->scheme,
        ], true);
    }
}
