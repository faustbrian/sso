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
 * Pass-through JSON resource for SCIM group payloads.
 *
 * Group adapters already emit SCIM-shaped arrays, so the resource preserves
 * that structure without Laravel's default wrapper or transformation logic.
 * This allows controllers to keep using resource responses for headers and
 * status codes without introducing a second serialization layer.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class ScimGroupResource extends JsonResource
{
    #[Override()]
    public static $wrap;

    /**
     * Return the underlying SCIM payload as-is when it is array-shaped.
     *
     * Non-array resources degrade to an empty payload to avoid leaking
     * unsupported resource shapes into the SCIM response body.
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
