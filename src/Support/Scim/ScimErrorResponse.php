<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Support\Scim;

use Cline\SSO\Exceptions\ScimHttpResponseException;
use Illuminate\Http\JsonResponse;

use function is_string;
use function response;

/**
 * Factory for SCIM-compliant error responses and exceptions.
 *
 * Laravel's default validation and exception responses do not match the SCIM
 * media type or payload shape. This helper centralizes the required schema,
 * status coercion, and optional SCIM error typing for controllers, middleware,
 * and form requests so the protocol surface stays consistent.
 *
 * Keeping response construction here ensures every SCIM failure path uses the
 * same envelope, whether the error originated from validation, authentication,
 * or a missing resource.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class ScimErrorResponse
{
    /**
     * Build an `application/scim+json` error response payload.
     *
     * The HTTP status is duplicated into the SCIM payload as a string because
     * RFC 7644 error documents represent `status` textually.
     */
    public static function make(string $detail, int $status, ?string $scimType = null): JsonResponse
    {
        $payload = [
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:Error'],
            'detail' => $detail,
            'status' => (string) $status,
        ];

        if (is_string($scimType) && $scimType !== '') {
            $payload['scimType'] = $scimType;
        }

        return response()->json($payload, $status, [
            'Content-Type' => 'application/scim+json',
        ]);
    }

    /**
     * Raise an HTTP response exception containing a SCIM error response.
     *
     * Throwing a response exception lets callers abort immediately while still
     * returning a fully formed SCIM error document.
     */
    public static function throw(string $detail, int $status, ?string $scimType = null): never
    {
        throw ScimHttpResponseException::fromResponse(self::make(
            detail: $detail,
            status: $status,
            scimType: $scimType,
        ));
    }
}
