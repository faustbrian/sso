<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Http\Requests;

/**
 * Validate SCIM PATCH payloads for group updates.
 *
 * The request constrains callers to the RFC 7644 operations envelope used by
 * the package while deliberately leaving attribute-specific semantics to the
 * configured SCIM group adapter. This keeps protocol-shape validation in the
 * HTTP layer and business interpretation in the adapter layer.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class PatchScimGroupRequest extends ScimFormRequest
{
    /**
     * Authorization is handled by upstream SCIM middleware.
     *
     * By the time this request executes, bearer-token validation has already
     * established whether the caller may reach the endpoint.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Return validation rules for RFC 7644 group patch operations.
     *
     * The rules guarantee at least one supported operation while allowing the
     * adapter to interpret paths and values for its own domain model. Operation
     * verbs are normalized only by validation membership, not by case
     * conversion, so adapters can decide whether to canonicalize further.
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
            'Operations.*.value' => ['sometimes', 'array'],
            'Operations.*.value.*.value' => ['required_with:Operations.*.value', 'string', 'max:255'],
        ];
    }
}
