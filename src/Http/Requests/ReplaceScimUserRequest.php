<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Http\Requests;

/**
 * Validates full-resource replacement payloads for SCIM users.
 *
 * Replacement requires the same core fields as creation because the request is
 * treated as an authoritative representation of the user resource. Reusing the
 * creation rules ensures the package applies the same minimum shape guarantees
 * whether a user is created or replaced.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class ReplaceScimUserRequest extends ScimFormRequest
{
    /**
     * Authorization is handled by upstream SCIM middleware.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Return the validation rules for SCIM user replacement.
     *
     * Delegating to {@see StoreScimUserRequest} keeps create and replace
     * semantics aligned and avoids silent drift between the two entry points.
     *
     * @return array<string, array<int, string>>
     */
    public function rules(): array
    {
        return new StoreScimUserRequest()->rules();
    }
}
