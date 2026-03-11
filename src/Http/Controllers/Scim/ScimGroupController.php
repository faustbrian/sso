<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Http\Controllers\Scim;

use Cline\SSO\Contracts\AuditSinkInterface;
use Cline\SSO\Contracts\ScimGroupAdapterInterface;
use Cline\SSO\Data\SsoProviderRecord;
use Cline\SSO\Exceptions\MissingScimProviderContextException;
use Cline\SSO\Http\Requests\PatchScimGroupRequest;
use Cline\SSO\Http\Requests\StoreScimGroupRequest;
use Cline\SSO\Http\Resources\ScimGroupResource;
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
 * SCIM group endpoint controller.
 *
 * This controller owns the HTTP boundary for SCIM group resources. It turns
 * authenticated requests into adapter calls, wraps results in SCIM-compliant
 * envelopes, and records audit events for mutating operations while leaving
 * group persistence and mapping rules to the configured adapter.
 *
 * The controller assumes SCIM authentication middleware has already attached a
 * provider context. That shared invariant lets every action remain focused on
 * protocol translation instead of repeating token resolution logic.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class ScimGroupController
{
    /**
     * @param ScimGroupAdapterInterface $adapter Adapter responsible for group
     *                                           listing and mutation
     * @param AuditSinkInterface        $audit   Sink used to record successful
     *                                           write operations
     */
    public function __construct(
        private ScimGroupAdapterInterface $adapter,
        private AuditSinkInterface $audit,
    ) {}

    /**
     * Return the provider's current group collection in SCIM list format.
     *
     * Even though the adapter returns raw resource arrays, the controller keeps
     * pagination metadata and SCIM media types consistent for all clients. The
     * list envelope is static because pagination is not delegated to adapters in
     * this package version.
     */
    public function index(Request $request): JsonResponse
    {
        $groups = $this->adapter->list($this->provider($request));

        return response()->json([
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
            'totalResults' => count($groups),
            'itemsPerPage' => count($groups),
            'startIndex' => 1,
            'Resources' => $groups,
        ], headers: ['Content-Type' => 'application/scim+json']);
    }

    /**
     * Create a new group resource for the authenticated provider.
     *
     * The validated payload is forwarded as-is to the adapter. Auditing happens
     * after creation so the recorded payload reflects the stored resource rather
     * than the pre-normalized request body.
     */
    public function store(StoreScimGroupRequest $request): JsonResponse
    {
        $provider = $this->provider($request);

        /** @var array<string, mixed> $payload */
        $payload = $request->validated();
        $resource = $this->adapter->create($provider, $payload);
        $this->audit->record('scim_group_created', $provider, ['resource' => $resource]);

        return new ScimGroupResource($resource)
            ->response()
            ->setStatusCode(Response::HTTP_CREATED)
            ->header('Content-Type', 'application/scim+json');
    }

    /**
     * Return a single group resource by its SCIM identifier.
     *
     * Missing groups are converted into SCIM error payloads instead of generic
     * framework exceptions so clients receive standards-compliant responses.
     */
    public function show(Request $request, string $group): ScimGroupResource
    {
        $resource = $this->adapter->find($this->provider($request), $group);

        if (!is_array($resource)) {
            ScimErrorResponse::throw($this->message('sso::sso.scim.errors.group_not_found'), 404);
        }

        return new ScimGroupResource($resource);
    }

    /**
     * Apply RFC 7644 PATCH operations to an existing group.
     *
     * Payload structure is validated upstream by the form request; the
     * controller only forwards normalized data and wraps the updated resource.
     * Adapter exceptions are allowed to bubble so SCIM-aware error handling can
     * shape the final response.
     */
    public function patch(PatchScimGroupRequest $request, string $group): ScimGroupResource
    {
        /** @var array<string, mixed> $payload */
        $payload = $request->validated();

        return new ScimGroupResource($this->adapter->patch($this->provider($request), $group, $payload));
    }

    /**
     * Delete a group resource and emit the related audit event.
     *
     * Successful deletions return an empty `204` response because SCIM uses the
     * status code, not a response body, to signal completion.
     */
    public function destroy(Request $request, string $group): JsonResponse
    {
        $provider = $this->provider($request);
        $this->adapter->delete($provider, $group);
        $this->audit->record('scim_group_deleted', $provider, ['group_id' => $group]);

        return response()->json([], 204, ['Content-Type' => 'application/scim+json']);
    }

    /**
     * Read the provider context attached by SCIM authentication middleware.
     *
     * This is treated as a required invariant. If the attribute is absent, the
     * request pipeline is misconfigured rather than merely unauthenticated.
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
     * Falling back to the key preserves deterministic error strings when a
     * translation entry is missing, which is preferable to emitting an empty
     * detail value in a SCIM error payload.
     */
    private function message(string $key): string
    {
        $message = __($key);

        return is_string($message) ? $message : $key;
    }
}
