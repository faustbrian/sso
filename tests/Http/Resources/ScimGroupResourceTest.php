<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Http\Resources\ScimGroupResource;
use Illuminate\Http\Request;

it('returns the group payload when the resource is an array', function (): void {
    $payload = [
        'id' => 'group-1',
        'displayName' => 'Engineering',
    ];

    expect(
        new ScimGroupResource($payload)->toArray(Request::create('/')),
    )
        ->toBe($payload);
});

it('returns an empty payload for non array scim groups', function (): void {
    expect(
        new ScimGroupResource('invalid')->toArray(Request::create('/')),
    )
        ->toBe([]);
});
