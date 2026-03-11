<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Http\Controllers\Scim;

use Illuminate\Http\JsonResponse;

use function __;
use function response;

/**
 * Publish the SCIM schemas advertised by the package.
 *
 * These discovery documents are static package metadata backed by translation
 * strings so clients can bootstrap themselves without querying adapter-specific
 * storage layers. The controller therefore acts as protocol metadata, not as a
 * view over provider-owned domain state.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class ScimSchemaController
{
    /**
     * Return the schema catalogue for core resources and discovery documents.
     *
     * Because the response is package-defined, the controller can advertise the
     * full schema catalogue without inspecting runtime adapters or repositories.
     */
    public function index(): JsonResponse
    {
        return response()->json([
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
            'totalResults' => 4,
            'itemsPerPage' => 4,
            'startIndex' => 1,
            'Resources' => [
                ['id' => 'urn:ietf:params:scim:schemas:core:2.0:User', 'name' => 'User', 'description' => __('sso::sso.scim.schemas.user')],
                ['id' => 'urn:ietf:params:scim:schemas:core:2.0:Group', 'name' => 'Group', 'description' => __('sso::sso.scim.schemas.group')],
                ['id' => 'urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig', 'name' => 'ServiceProviderConfig', 'description' => __('sso::sso.scim.schemas.service_provider_config')],
                ['id' => 'urn:ietf:params:scim:schemas:core:2.0:ResourceType', 'name' => 'ResourceType', 'description' => __('sso::sso.scim.schemas.resource_type')],
            ],
        ], headers: [
            'Content-Type' => 'application/scim+json',
        ]);
    }
}
