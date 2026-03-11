<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Http\Requests\PatchScimGroupRequest;
use Illuminate\Support\Facades\Validator;

it('authorizes patch scim group requests', function (): void {
    expect(
        new PatchScimGroupRequest()->authorize(),
    )->toBeTrue();
});

it('accepts a valid scim group patch payload', function (): void {
    $validator = Validator::make([
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [[
            'op' => 'Replace',
            'path' => 'members',
            'value' => [
                ['value' => 'group-member-1'],
            ],
        ]],
    ], new PatchScimGroupRequest()->rules());

    expect($validator->fails())->toBeFalse();
});

it('requires supported operations for group patch payloads', function (): void {
    $validator = Validator::make([
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [
            ['op' => 'Move'],
        ],
    ], new PatchScimGroupRequest()->rules());

    expect($validator->fails())->toBeTrue()
        ->and($validator->errors()->keys())->toContain('Operations.0.op');
});
