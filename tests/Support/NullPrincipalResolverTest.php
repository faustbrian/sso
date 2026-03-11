<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Support\NullPrincipalResolver;
use Tests\Fixtures\TestUser;

it('returns no linked principals from the null principal resolver', function (): void {
    $resolver = new NullPrincipalResolver();
    $principal = TestUser::query()->create([
        'email' => 'null-principal@example.test',
        'name' => 'Null Principal',
    ]);
    $identity = makeNullResolvedIdentity();

    expect($resolver->findPrincipalByEmail(makeNullProviderRecord(), 'user@example.test'))->toBeNull()
        ->and($resolver->findPrincipalByExternalIdentity(makeNullProviderRecord(), makeNullExternalIdentityRecord()))->toBeNull()
        ->and($resolver->canLinkPrincipal(makeNullProviderRecord(), $principal, $identity))->toBeFalse()
        ->and($resolver->provisionPrincipal(makeNullProviderRecord(), $identity))->toBeNull()
        ->and($resolver->canSignIn(makeNullProviderRecord(), $principal))->toBeFalse();

    $resolver->afterLogin(makeNullProviderRecord(), $principal, $identity);

    expect(true)->toBeTrue();
});
