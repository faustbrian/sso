<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Http\Requests;

/**
 * Validates SCIM patch documents targeting user resources.
 *
 * The request only enforces the envelope and operation structure; the adapter
 * remains responsible for interpreting each operation path and value. This
 * separation allows applications to support different user attributes without
 * rewriting the SCIM protocol boundary.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class PatchScimUserRequest extends ScimFormRequest
{
    /**
     * Authorization is handled by upstream SCIM middleware.
     *
     * By the time validation runs, bearer-token authentication has already
     * established whether the caller may reach the endpoint.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Return the validation rules for SCIM user patch operations.
     *
     * The request validates protocol shape only and intentionally avoids
     * declaring attribute-specific rules for adapter-defined patch behavior.
     *
     * @return array<string, array<int, string>>
     */
    public function rules(): array
    {
        return [
            'schemas' => ['required', 'array', 'min:1'],
            'schemas.*' => ['string'],
            'Operations' => ['required', 'array', 'min:1'],
            'Operations.*.op' => ['required', 'string', 'in:Add,Remove,Replace,add,remove,replace'],
            'Operations.*.path' => ['nullable', 'string', 'max:255'],
        ];
    }
}
