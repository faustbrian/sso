<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Support\NullAuditSink;

it('silently discards events in the null audit sink', function (): void {
    new NullAuditSink()->record('login.succeeded', makeNullProviderRecord(), ['user' => '1']);

    expect(true)->toBeTrue();
});
