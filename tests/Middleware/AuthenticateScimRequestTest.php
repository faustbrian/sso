<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Exceptions\InvalidScimMiddlewareResponseException;
use Cline\SSO\Http\Middleware\AuthenticateScimRequest;
use Cline\SSO\Models\SsoProvider;
use Cline\SSO\SsoManager;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

it('attaches the provider context and updates usage when the bearer token is valid', function (): void {
    $provider = SsoProvider::query()->create([
        'id' => 'provider-scim-record',
        'tenant_id' => 1,
        'driver' => 'oidc',
        'scheme' => 'azure-acme',
        'display_name' => 'Acme Azure AD',
        'authority' => 'https://login.example.test/acme/v2.0',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'enabled' => true,
        'scim_enabled' => true,
        'scim_token_hash' => hash('sha256', 'shipit-scim-token'),
        'validate_issuer' => false,
    ]);
    $request = Request::create('/scim/v2/Users', Symfony\Component\HttpFoundation\Request::METHOD_GET, server: [
        'HTTP_AUTHORIZATION' => 'Bearer shipit-scim-token',
    ]);

    $middleware = new AuthenticateScimRequest(resolve(SsoManager::class));

    $response = $middleware->handle($request, function (Request $request): Response {
        expect($request->attributes->get('scimProvider'))->not->toBeNull();

        return new Response('ok');
    });

    expect($response->getContent())->toBe('ok')
        ->and($provider->fresh()->scim_last_used_at)->not->toBeNull();
});

it('throws when the downstream scim pipeline does not return a response instance', function (): void {
    SsoProvider::query()->create([
        'id' => 'provider-scim-invalid-response',
        'tenant_id' => 1,
        'driver' => 'oidc',
        'scheme' => 'azure-invalid-response',
        'display_name' => 'Acme Azure AD',
        'authority' => 'https://login.example.test/acme/v2.0',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'enabled' => true,
        'scim_enabled' => true,
        'scim_token_hash' => hash('sha256', 'shipit-scim-token'),
        'validate_issuer' => false,
    ]);
    $request = Request::create('/scim/v2/Users', Symfony\Component\HttpFoundation\Request::METHOD_GET, server: [
        'HTTP_AUTHORIZATION' => 'Bearer shipit-scim-token',
    ]);

    $middleware = new AuthenticateScimRequest(resolve(SsoManager::class));

    expect(fn (): mixed => $middleware->handle($request, static fn (): string => 'invalid-response'))
        ->toThrow(InvalidScimMiddlewareResponseException::class);
});
