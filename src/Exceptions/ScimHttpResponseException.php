<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Http\JsonResponse;

/**
 * Wraps a prepared SCIM error response in an exception for early aborts.
 *
 * This exception bridges the package's SCIM response factory with Laravel's
 * exception pipeline. It allows controllers and middleware to stop execution
 * immediately while preserving the already-built `application/scim+json`
 * payload that should be returned to the client.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class ScimHttpResponseException extends HttpResponseException implements SsoException
{
    /**
     * Create an exception that carries the provided SCIM response unchanged.
     *
     * The response is assumed to already contain the correct status code,
     * media type, and RFC 7644 error payload. This factory exists so call
     * sites do not need to instantiate framework exceptions directly.
     */
    public static function fromResponse(JsonResponse $response): self
    {
        return new self($response);
    }
}
