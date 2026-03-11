<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Configuration\Configuration;
use Cline\SSO\Exceptions\InvalidDriverClassConfigurationException;
use Tests\Fixtures\TestStrategy;

it('rejects invalid configured driver classes', function (): void {
    config()->set('sso.drivers', [
        'valid' => TestStrategy::class,
        'invalid' => '',
    ]);

    expect(fn (): array => Configuration::drivers()->all())
        ->toThrow(InvalidDriverClassConfigurationException::class);
});
