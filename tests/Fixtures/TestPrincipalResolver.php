<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Fixtures;

use Cline\SSO\Contracts\PrincipalResolverInterface;
use Cline\SSO\Data\ExternalIdentityRecord;
use Cline\SSO\Data\PrincipalReference;
use Cline\SSO\Data\SsoProviderRecord;
use Cline\SSO\ValueObjects\ResolvedIdentity;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

use function is_scalar;
use function is_string;
use function mb_strtolower;

/**
 * @author Brian Faust <brian@cline.sh>
 */
final class TestPrincipalResolver implements PrincipalResolverInterface
{
    public static bool $allowLink = true;

    public static bool $allowSignIn = true;

    public static bool $allowProvision = true;

    public function findPrincipalByEmail(SsoProviderRecord $provider, string $email): ?Authenticatable
    {
        return TestUser::query()->whereRaw('LOWER(email) = ?', [mb_strtolower($email)])->first();
    }

    public function findPrincipalByExternalIdentity(SsoProviderRecord $provider, ExternalIdentityRecord $identity): ?Authenticatable
    {
        return TestUser::query()->find($identity->linkedPrincipal->key);
    }

    public function canLinkPrincipal(SsoProviderRecord $provider, Authenticatable $principal, ResolvedIdentity $identity): bool
    {
        return self::$allowLink;
    }

    public function provisionPrincipal(SsoProviderRecord $provider, ResolvedIdentity $identity): ?Authenticatable
    {
        if (!self::$allowProvision || !is_string($identity->email) || $identity->email === '') {
            return null;
        }

        $name = $identity->attributes['name'] ?? 'Provisioned User';

        return TestUser::query()->create([
            'email' => mb_strtolower($identity->email),
            'name' => is_scalar($name) ? (string) $name : 'Provisioned User',
            'password' => 'secret',
        ]);
    }

    public function principalReference(Authenticatable $principal): PrincipalReference
    {
        $type = $principal instanceof Model ? $principal->getMorphClass() : TestUser::class;
        $identifier = $principal->getAuthIdentifier();

        return new PrincipalReference($type, is_scalar($identifier) ? (string) $identifier : '');
    }

    public function canSignIn(SsoProviderRecord $provider, Authenticatable $principal): bool
    {
        return self::$allowSignIn;
    }

    public function afterLogin(SsoProviderRecord $provider, Authenticatable $principal, ResolvedIdentity $identity): void {}
}
