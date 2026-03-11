<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Http\Resources\ScimUserResource;
use Illuminate\Http\Request;

it('returns the user payload when the resource is an array', function (): void {
    $payload = [
        'id' => 'user-1',
        'userName' => 'user@example.test',
    ];

    expect(
        new ScimUserResource($payload)->toArray(Request::create('/')),
    )
        ->toBe($payload);
});

it('returns an empty payload for non array scim users', function (): void {
    expect(
        new ScimUserResource('invalid')->toArray(Request::create('/')),
    )
        ->toBe([]);
});
