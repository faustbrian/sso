<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Http\Controllers\Scim;

use Cline\SSO\Contracts\AuditSinkInterface;
use Cline\SSO\Contracts\ScimUserAdapterInterface;
use Cline\SSO\Data\SsoProviderRecord;
use Cline\SSO\Exceptions\MissingScimProviderContextException;
use Cline\SSO\Http\Requests\PatchScimUserRequest;
use Cline\SSO\Http\Requests\ReplaceScimUserRequest;
use Cline\SSO\Http\Requests\StoreScimUserRequest;
use Cline\SSO\Http\Resources\ScimUserResource;
use Cline\SSO\Support\Scim\ScimErrorResponse;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

use function __;
use function count;
use function is_array;
use function is_string;
use function response;

/**
 * SCIM user endpoint controller.
 *
 * This controller owns the protocol boundary for SCIM user operations. It
 * turns validated requests into adapter calls, wraps responses as SCIM user
 * resources, and records audit events for writes while leaving actual user
 * persistence and attribute mapping to the configured adapter.
 *
 * Like the other SCIM controllers, it assumes provider context has already
 * been established by middleware. That lets the controller focus on SCIM
 * request/response semantics rather than authentication concerns.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class ScimUserController
{
    /**
     * @param ScimUserAdapterInterface $adapter Adapter responsible for SCIM user
     *                                          lookup and mutation
     * @param AuditSinkInterface       $audit   Sink used to record successful
     *                                          create operations
     */
    public function __construct(
        private ScimUserAdapterInterface $adapter,
        private AuditSinkInterface $audit,
    ) {}

    /**
     * Return the provider's user collection in SCIM list format.
     *
     * Any incoming filter expression is passed straight through so adapter
     * implementations can interpret SCIM filtering in their own domain layer.
     * The controller stays deliberately agnostic about supported filter syntax.
     */
    public function index(Request $request): JsonResponse
    {
        $provider = $this->provider($request);
        $users = $this->adapter->list($provider, $request->string('filter')->toString());

        return response()->json([
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
            'totalResults' => count($users),
            'itemsPerPage' => count($users),
            'startIndex' => 1,
            'Resources' => $users,
        ], headers: ['Content-Type' => 'application/scim+json']);
    }

    /**
     * Create a new user resource for the authenticated provider.
     *
     * Auditing occurs after the adapter returns the canonical resource so the
     * audit sink sees the stored representation rather than raw input.
     */
    public function store(StoreScimUserRequest $request): JsonResponse
    {
        $provider = $this->provider($request);

        /** @var array<string, mixed> $payload */
        $payload = $request->validated();
        $resource = $this->adapter->create($provider, $payload);
        $this->audit->record('scim_user_created', $provider, ['resource' => $resource]);

        return new ScimUserResource($resource)
            ->response()
            ->setStatusCode(Response::HTTP_CREATED)
            ->header('Content-Type', 'application/scim+json');
    }

    /**
     * Return a single user resource by SCIM identifier.
     *
     * Missing resources are surfaced as SCIM errors rather than generic Laravel
     * exceptions so SCIM clients receive a standards-compliant error payload.
     */
    public function show(Request $request, string $user): ScimUserResource
    {
        $resource = $this->adapter->find($this->provider($request), $user);

        if (!is_array($resource)) {
            ScimErrorResponse::throw($this->message('sso::sso.scim.errors.user_not_found'), 404);
        }

        return new ScimUserResource($resource);
    }

    /**
     * Replace a user resource with a complete SCIM document.
     *
     * The adapter decides how omitted attributes are handled; the controller's
     * responsibility is to forward validated input and wrap the resulting
     * representation. This preserves a clear separation between protocol rules
     * and application-specific user persistence semantics.
     */
    public function replace(ReplaceScimUserRequest $request, string $user): ScimUserResource
    {
        /** @var array<string, mixed> $payload */
        $payload = $request->validated();

        return new ScimUserResource($this->adapter->replace($this->provider($request), $user, $payload));
    }

    /**
     * Apply RFC 7644 PATCH operations to an existing user resource.
     *
     * Patch document validation happens in the form request so the controller
     * can treat the payload as normalized SCIM operations.
     */
    public function patch(PatchScimUserRequest $request, string $user): ScimUserResource
    {
        /** @var array<string, mixed> $payload */
        $payload = $request->validated();

        return new ScimUserResource($this->adapter->patch($this->provider($request), $user, $payload));
    }

    /**
     * Read the provider context attached by SCIM authentication middleware.
     *
     * Missing context is treated as pipeline misconfiguration, not as an
     * ordinary authorization failure.
     */
    private function provider(Request $request): SsoProviderRecord
    {
        $provider = $request->attributes->get('scimProvider');

        if (!$provider instanceof SsoProviderRecord) {
            throw MissingScimProviderContextException::create();
        }

        return $provider;
    }

    /**
     * Resolve a translated message key into a stable string payload.
     *
     * Falling back to the key preserves deterministic error detail when a
     * translation entry is missing.
     */
    private function message(string $key): string
    {
        $message = __($key);

        return is_string($message) ? $message : $key;
    }
}
