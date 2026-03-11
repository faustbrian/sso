<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Support\NullScimGroupAdapter;

it('returns empty results from the null scim group adapter', function (): void {
    $adapter = new NullScimGroupAdapter();

    expect($adapter->list(makeNullProviderRecord()))->toBe([])
        ->and($adapter->find(makeNullProviderRecord(), 'group-1'))->toBeNull()
        ->and($adapter->create(makeNullProviderRecord(), ['displayName' => 'Group']))
        ->toBe(['displayName' => 'Group'])
        ->and($adapter->patch(makeNullProviderRecord(), 'group-1', [['op' => 'replace']]))
        ->toBe([['op' => 'replace']]);

    $adapter->delete(makeNullProviderRecord(), 'group-1');

    expect(true)->toBeTrue();
});
