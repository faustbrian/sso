<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Data\ExternalIdentityRecord;
use Cline\SSO\Data\PrincipalReference;

it('creates a copy with a new email snapshot', function (): void {
    $principal = new PrincipalReference('users', '42');
    $record = new ExternalIdentityRecord(
        id: 'identity-1',
        emailSnapshot: 'before@example.test',
        issuer: 'https://issuer.example.test',
        linkedPrincipal: $principal,
        providerId: 'provider-1',
        subject: 'subject-1',
    );

    $updated = $record->withEmailSnapshot('after@example.test');

    expect($updated)->not->toBe($record)
        ->and($updated->id)->toBe('identity-1')
        ->and($updated->emailSnapshot)->toBe('after@example.test')
        ->and($updated->issuer)->toBe('https://issuer.example.test')
        ->and($updated->linkedPrincipal)->toBe($principal)
        ->and($updated->providerId)->toBe('provider-1')
        ->and($updated->subject)->toBe('subject-1')
        ->and($record->emailSnapshot)->toBe('before@example.test');
});
