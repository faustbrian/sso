<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Http\Requests;

/**
 * Validates payloads used to create SCIM group resources.
 *
 * Group creation requires a display name while allowing membership payloads to
 * be supplied for adapters that support initial member assignment. The request
 * intentionally validates only the baseline structure that every adapter can
 * rely on before applying application-specific group semantics.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class StoreScimGroupRequest extends ScimFormRequest
{
    /**
     * Authorization is handled by upstream SCIM middleware.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Return the validation rules for SCIM group creation.
     *
     * Membership entries are validated only to the extent needed for SCIM
     * shape correctness; adapters remain responsible for deciding whether those
     * referenced members are valid in the local domain.
     *
     * @return array<string, array<int, string>>
     */
    public function rules(): array
    {
        return [
            'schemas' => ['required', 'array', 'min:1'],
            'schemas.*' => ['string'],
            'displayName' => ['required', 'string', 'max:255'],
            'members' => ['sometimes', 'array'],
            'members.*.value' => ['required_with:members', 'string', 'max:255'],
        ];
    }
}
