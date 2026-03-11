<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Support;

use Cline\SSO\Contracts\PrincipalResolverInterface;
use Cline\SSO\Data\ExternalIdentityRecord;
use Cline\SSO\Data\PrincipalReference;
use Cline\SSO\Data\SsoProviderRecord;
use Cline\SSO\ValueObjects\ResolvedIdentity;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Null-object principal resolver that fails closed for every identity
 * operation.
 *
 * This is the package's safe default before the host application supplies a
 * real principal-resolution policy. Every lookup returns no principal,
 * automatic linking and provisioning are disabled, and sign-in authorization is
 * denied so no accidental account mapping can occur merely because the package
 * was installed.
 *
 * The abstraction exists to let the package register a complete
 * `PrincipalResolverInterface` implementation at boot even when the host
 * application has not yet decided how remote identities should map onto local
 * accounts. Its invariant is simple: without explicit application policy, all
 * identity operations fail closed.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class NullPrincipalResolver implements PrincipalResolverInterface
{
    /**
     * Refuse to resolve a principal by email address.
     *
     * Returning `null` keeps first-login discovery from silently binding a
     * remote identity to a local account based on email heuristics alone.
     */
    public function findPrincipalByEmail(SsoProviderRecord $provider, string $email): ?Authenticatable
    {
        return null;
    }

    /**
     * Refuse to resolve a principal from an existing external identity record.
     *
     * Even persisted identity links are ignored in fail-closed mode so the host
     * application cannot accidentally authenticate users before supplying an
     * explicit resolver policy.
     */
    public function findPrincipalByExternalIdentity(SsoProviderRecord $provider, ExternalIdentityRecord $identity): ?Authenticatable
    {
        return null;
    }

    /**
     * Prevent automatic linking of a remote identity to a local account.
     *
     * The default package posture is that linking requires application-owned
     * authorization policy, never implicit approval.
     */
    public function canLinkPrincipal(SsoProviderRecord $provider, Authenticatable $principal, ResolvedIdentity $identity): bool
    {
        return false;
    }

    /**
     * Prevent automatic provisioning of a new local account.
     *
     * Returning `null` ensures install-time defaults cannot create users or
     * tenant records as a side effect of an incoming SSO assertion.
     */
    public function provisionPrincipal(SsoProviderRecord $provider, ResolvedIdentity $identity): ?Authenticatable
    {
        return null;
    }

    /**
     * Return an intentionally incomplete principal reference placeholder.
     *
     * The empty key makes it obvious that this resolver is not suitable for
     * persistence workflows until the application supplies a real
     * implementation. The method exists only to satisfy the contract during
     * fail-closed mode and should not be treated as a persistable identity
     * reference.
     */
    public function principalReference(Authenticatable $principal): PrincipalReference
    {
        return new PrincipalReference($principal::class, '');
    }

    /**
     * Deny sign-in for every resolved local principal.
     *
     * Even if another part of the system hands this resolver an
     * `Authenticatable`, the resolver's contract remains fail closed.
     */
    public function canSignIn(SsoProviderRecord $provider, Authenticatable $principal): bool
    {
        return false;
    }

    /**
     * Perform no post-login side effects.
     *
     * The null-object resolver never mutates local state, emits follow-up
     * behavior, or records policy-driven login hooks.
     */
    public function afterLogin(SsoProviderRecord $provider, Authenticatable $principal, ResolvedIdentity $identity): void {}
}
