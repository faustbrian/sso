<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Http\Requests\PatchScimUserRequest;
use Illuminate\Support\Facades\Validator;

it('authorizes patch scim user requests', function (): void {
    expect(
        new PatchScimUserRequest()->authorize(),
    )->toBeTrue();
});

it('accepts a valid scim user patch payload', function (): void {
    $validator = Validator::make([
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [[
            'op' => 'add',
            'path' => 'active',
        ]],
    ], new PatchScimUserRequest()->rules());

    expect($validator->fails())->toBeFalse();
});

it('requires operations for user patch payloads', function (): void {
    $validator = Validator::make([
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [],
    ], new PatchScimUserRequest()->rules());

    expect($validator->fails())->toBeTrue()
        ->and($validator->errors()->keys())->toContain('Operations');
});
