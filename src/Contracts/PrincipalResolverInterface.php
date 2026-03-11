<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Contracts;

use Cline\SSO\Data\ExternalIdentityRecord;
use Cline\SSO\Data\PrincipalReference;
use Cline\SSO\Data\SsoProviderRecord;
use Cline\SSO\ValueObjects\ResolvedIdentity;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Resolves local principals from provider-issued identities.
 *
 * This contract is the package's policy boundary for account linking,
 * provisioning, and sign-in authorization. The package can validate a remote
 * identity, but only the host application can decide how that identity maps to
 * a local principal and whether that principal should be allowed to continue.
 *
 * Implementations therefore own the most application-specific parts of the
 * login lifecycle: email heuristics, linked-identity lookups, automatic
 * provisioning, final authorization, and any post-login side effects.
 *
 * Callers should expect these methods to be invoked in a staged resolution
 * order: attempt durable link recovery, optionally fall back to email lookup,
 * validate whether linking is allowed, optionally provision, then perform a
 * final sign-in authorization check and post-login side effects.
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface PrincipalResolverInterface
{
    /**
     * Find a local principal by email when the provider returned an address
     * claim.
     *
     * This is typically the first heuristic used before a durable external
     * identity link exists. Returning `null` tells the package to continue its
     * resolution pipeline rather than treating the login as failed outright.
     */
    public function findPrincipalByEmail(SsoProviderRecord $provider, string $email): ?Authenticatable;

    /**
     * Find a local principal through a previously stored external identity
     * mapping.
     *
     * Implementations should treat the supplied identity record as
     * authoritative evidence of a prior link unless the referenced account no
     * longer exists. If the principal cannot be recovered, callers may decide
     * whether to relink, provision, or deny access based on package policy.
     */
    public function findPrincipalByExternalIdentity(SsoProviderRecord $provider, ExternalIdentityRecord $identity): ?Authenticatable;

    /**
     * Determine whether the given principal may be linked to the resolved
     * identity.
     *
     * This hook allows applications to enforce policies such as owner
     * isolation, domain restrictions, or manual approval before persisting a
     * new external identity link. It should be side-effect free because callers
     * may invoke it before deciding whether to persist a new durable mapping.
     */
    public function canLinkPrincipal(SsoProviderRecord $provider, Authenticatable $principal, ResolvedIdentity $identity): bool;

    /**
     * Provision a new local principal for the resolved identity, if allowed.
     *
     * Returning `null` indicates that automatic provisioning is not permitted
     * for the resolved identity under the application's policies. When a
     * principal is returned, callers treat it as a newly created or newly
     * activated local account that may immediately proceed to linking and
     * sign-in checks.
     */
    public function provisionPrincipal(SsoProviderRecord $provider, ResolvedIdentity $identity): ?Authenticatable;

    /**
     * Build the principal reference persisted for a linked authenticatable
     * principal.
     *
     * The returned reference must remain stable enough for future logins to
     * recover the same local identity from repository data alone. This
     * abstraction exists so the package can persist link data without assuming
     * every application uses the same authenticatable model key semantics.
     */
    public function principalReference(Authenticatable $principal): PrincipalReference;

    /**
     * Determine whether the principal is currently allowed to sign in via the
     * provider.
     *
     * This final authorization check runs after the principal has been
     * resolved or provisioned but before the package completes the login.
     * Returning `false` should deny the sign-in without mutating link state so
     * policy enforcement stays separate from persistence concerns.
     */
    public function canSignIn(SsoProviderRecord $provider, Authenticatable $principal): bool;

    /**
     * Run any application-specific side effects after a successful login.
     *
     * Implementations can use this hook for updates such as last-login stamps,
     * synchronization, or security notifications that should happen only after
     * authentication has fully succeeded. Any side effects here run after the
     * package has decided the login is valid, so failures should be handled
     * with that post-authentication timing in mind.
     */
    public function afterLogin(SsoProviderRecord $provider, Authenticatable $principal, ResolvedIdentity $identity): void;
}
