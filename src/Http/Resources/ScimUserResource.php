<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Override;

use function is_array;

/**
 * Pass-through JSON resource for SCIM user payloads.
 *
 * Adapter implementations already return SCIM-shaped arrays, so the resource's
 * job is mainly to opt out of Laravel's default wrapping while retaining the
 * convenience of resource responses in controllers. It exists to preserve a
 * consistent controller pattern, not to transform domain data.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class ScimUserResource extends JsonResource
{
    #[Override()]
    public static $wrap;

    /**
     * Return the underlying SCIM payload as-is when it is array-shaped.
     *
     * Non-array resources degrade to an empty payload to keep the response
     * shape deterministic.
     *
     * @return array<string, mixed>
     */
    #[Override()]
    public function toArray(Request $request): array
    {
        $resource = $this->resource;

        if (!is_array($resource)) {
            return [];
        }

        /** @var array<string, mixed> $resource */
        return $resource;
    }
}
