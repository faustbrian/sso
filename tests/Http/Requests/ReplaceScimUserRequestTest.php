<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Http\Requests\ReplaceScimUserRequest;
use Cline\SSO\Http\Requests\StoreScimUserRequest;

it('authorizes replace scim user requests', function (): void {
    expect(
        new ReplaceScimUserRequest()->authorize(),
    )->toBeTrue();
});

it('reuses the store request rules for user replacement', function (): void {
    expect(
        new ReplaceScimUserRequest()->rules(),
    )
        ->toBe(
            new StoreScimUserRequest()->rules(),
        );
});
