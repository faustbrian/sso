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
 * Return the package's SCIM service provider capability document.
 *
 * This endpoint advertises protocol support at the package level rather than on
 * a per-provider basis, so the response is intentionally static. Clients can
 * use it to discover which parts of RFC 7644 the package implements before
 * attempting feature-specific requests.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class ScimServiceProviderConfigController
{
    /**
     * Publish supported SCIM capabilities and authentication scheme details.
     *
     * Unsupported features are reported explicitly so clients do not infer
     * behavior the package cannot guarantee. The advertised authentication
     * scheme also documents that SCIM access is provider-token based.
     */
    public function __invoke(): JsonResponse
    {
        return response()->json([
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
            'patch' => ['supported' => true],
            'bulk' => ['supported' => false, 'maxOperations' => 0, 'maxPayloadSize' => 0],
            'filter' => ['supported' => true, 'maxResults' => 100],
            'changePassword' => ['supported' => false],
            'sort' => ['supported' => false],
            'etag' => ['supported' => false],
            'authenticationSchemes' => [[
                'type' => 'oauthbearertoken',
                'name' => __('sso::sso.scim.schemas.authentication_scheme_name'),
                'description' => __('sso::sso.scim.schemas.authentication_scheme'),
                'primary' => true,
            ]],
        ], headers: [
            'Content-Type' => 'application/scim+json',
        ]);
    }
}
