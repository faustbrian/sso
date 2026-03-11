<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Http\Requests;

use Cline\SSO\Support\Scim\ScimErrorResponse;
use Illuminate\Contracts\Validation\Validator;
use Illuminate\Foundation\Http\FormRequest;
use Override;

/**
 * Base form request that translates Laravel validation failures into SCIM
 * protocol errors.
 *
 * SCIM clients expect `application/scim+json` responses with standardized
 * error payloads. Subclasses only define rules; this base class ensures any
 * validation failure is surfaced with the correct media type and error shape
 * instead of Laravel's default redirect or generic JSON behavior.
 *
 * Keeping that translation here lets the individual request classes focus on
 * SCIM payload structure rather than response formatting.
 *
 * @author Brian Faust <brian@cline.sh>
 */
abstract class ScimFormRequest extends FormRequest
{
    /**
     * Convert validation failures into SCIM `invalidValue` responses.
     *
     * The first validation error is used as the SCIM detail string so clients
     * receive a concise explanation without Laravel-specific error bag noise.
     */
    #[Override()]
    protected function failedValidation(Validator $validator): never
    {
        ScimErrorResponse::throw(
            detail: $validator->errors()->first(),
            status: 422,
            scimType: 'invalidValue',
        );
    }
}
