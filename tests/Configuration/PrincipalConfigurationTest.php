<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Configuration\Configuration;

it('falls back to the primary key type when principal type is absent', function (): void {
    config()->set('sso.foreign_keys.principal', [
        'column' => 'user_id',
        'owner_key' => 'id',
    ]);
    config()->set('sso.primary_key_type', 'uuid');

    expect(Configuration::principal()->keyType())->toBe('uuid');
});
