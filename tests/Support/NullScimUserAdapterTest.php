<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Support\NullScimUserAdapter;

it('returns empty results from the null scim user adapter', function (): void {
    $adapter = new NullScimUserAdapter();

    expect($adapter->list(makeNullProviderRecord()))->toBe([])
        ->and($adapter->find(makeNullProviderRecord(), 'user-1'))->toBeNull()
        ->and($adapter->create(makeNullProviderRecord(), ['userName' => 'user@example.test']))
        ->toBe(['userName' => 'user@example.test'])
        ->and($adapter->replace(makeNullProviderRecord(), 'user-1', ['userName' => 'user@example.test']))
        ->toBe(['userName' => 'user@example.test'])
        ->and($adapter->patch(makeNullProviderRecord(), 'user-1', [['op' => 'replace']]))
        ->toBe([['op' => 'replace']]);

    expect(true)->toBeTrue();
});
