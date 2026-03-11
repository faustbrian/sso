<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Http\Controllers\Scim;

use Illuminate\Http\JsonResponse;

use function response;

/**
 * Publish the static SCIM resource type catalogue supported by the package.
 *
 * The package currently exposes only `User` and `Group` resources, so this
 * controller returns a fixed discovery document instead of consulting adapter
 * state at runtime. That keeps discovery deterministic and independent of
 * whether a specific provider currently has any users or groups available.
 * The controller exists to satisfy the SCIM discovery surface with a stable,
 * package-level description of capability rather than a per-provider runtime
 * snapshot.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class ScimResourceTypeController
{
    /**
     * Return supported SCIM resource types using the standard list envelope.
     *
     * The response is intentionally static because resource-type support is a
     * package capability, not owner- or provider-specific state. The SCIM
     * content type is emitted explicitly so discovery clients can negotiate the
     * response correctly even when the rest of the host application defaults to
     * generic JSON responses.
     */
    public function index(): JsonResponse
    {
        return response()->json([
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
            'totalResults' => 2,
            'itemsPerPage' => 2,
            'startIndex' => 1,
            'Resources' => [
                ['id' => 'User', 'name' => 'User', 'endpoint' => '/Users', 'schema' => 'urn:ietf:params:scim:schemas:core:2.0:User'],
                ['id' => 'Group', 'name' => 'Group', 'endpoint' => '/Groups', 'schema' => 'urn:ietf:params:scim:schemas:core:2.0:Group'],
            ],
        ], headers: [
            'Content-Type' => 'application/scim+json',
        ]);
    }
}
