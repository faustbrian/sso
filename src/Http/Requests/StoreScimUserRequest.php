<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Http\Requests;

/**
 * Validates payloads used to create SCIM user resources.
 *
 * The rules enforce the minimal core attributes required by the package's
 * default SCIM user workflow while still allowing adapter-specific extension
 * data through nested structures. This gives adapters a predictable baseline
 * payload without over-constraining application-owned user schemas.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class StoreScimUserRequest extends ScimFormRequest
{
    /**
     * Authorization is handled by upstream SCIM middleware.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Return the validation rules for SCIM user creation.
     *
     * The rules guarantee the presence of a SCIM-compatible username while
     * treating optional nested attributes as adapter-owned concerns.
     *
     * @return array<string, array<int, string>>
     */
    public function rules(): array
    {
        return [
            'schemas' => ['required', 'array', 'min:1'],
            'schemas.*' => ['string'],
            'externalId' => ['nullable', 'string', 'max:255'],
            'userName' => ['required', 'email:rfc', 'max:255'],
            'active' => ['sometimes', 'boolean'],
            'name' => ['sometimes', 'array'],
            'name.formatted' => ['nullable', 'string', 'max:255'],
            'name.givenName' => ['nullable', 'string', 'max:255'],
            'name.familyName' => ['nullable', 'string', 'max:255'],
            'roles' => ['sometimes', 'array'],
            'roles.*.value' => ['required_with:roles', 'string', 'max:255'],
        ];
    }
}
