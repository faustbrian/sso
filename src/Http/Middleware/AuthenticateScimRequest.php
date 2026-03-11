<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Http\Middleware;

use Cline\SSO\Data\SsoProviderRecord;
use Cline\SSO\Exceptions\InvalidScimMiddlewareResponseException;
use Cline\SSO\SsoManager;
use Cline\SSO\Support\Scim\ScimErrorResponse;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

use function __;
use function hash;
use function is_string;
use function now;

/**
 * Authenticate SCIM API requests with provider-issued bearer tokens.
 *
 * This middleware establishes the provider context required by every SCIM
 * controller. It validates the bearer token, resolves the corresponding
 * provider, updates provider usage timestamps, and injects the provider record
 * into the request for downstream handlers.
 *
 * It is intentionally SCIM-aware rather than reusing Laravel's generic API
 * authentication patterns because SCIM clients expect protocol-specific error
 * payloads and because bearer tokens are scoped to providers, not users.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class AuthenticateScimRequest
{
    /**
     * @param SsoManager $sso Orchestration service used to resolve and update
     *                        provider records
     */
    public function __construct(
        private SsoManager $sso,
    ) {}

    /**
     * Validate the incoming bearer token and attach SCIM provider context.
     *
     * Authentication failures return SCIM-formatted errors instead of Laravel
     * auth responses so clients always receive protocol-compliant payloads. On
     * success, the provider record is attached to the request as the canonical
     * context for all downstream SCIM operations.
     */
    public function handle(Request $request, Closure $next): Response
    {
        $token = $request->bearerToken();

        if (!is_string($token) || $token === '') {
            return ScimErrorResponse::make($this->message('sso::sso.scim.errors.missing_bearer_token'), Response::HTTP_UNAUTHORIZED);
        }

        $provider = $this->sso->findProviderByScimTokenHash(hash('sha256', $token));

        if (!$provider instanceof SsoProviderRecord) {
            return ScimErrorResponse::make($this->message('sso::sso.scim.errors.invalid_bearer_token'), Response::HTTP_UNAUTHORIZED);
        }

        $this->sso->updateProvider($provider->id, [
            'scim_last_used_at' => now(),
        ]);

        $request->attributes->set('scimProvider', $provider);
        $response = $next($request);

        if (!$response instanceof Response) {
            throw InvalidScimMiddlewareResponseException::create();
        }

        return $response;
    }

    /**
     * Resolve a translated message key into a stable string payload.
     *
     * Falling back to the key prevents SCIM errors from losing their detail
     * field when translations are incomplete.
     */
    private function message(string $key): string
    {
        $message = __($key);

        return is_string($message) ? $message : $key;
    }
}
