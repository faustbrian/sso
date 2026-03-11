<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Configuration;

use Illuminate\Support\Facades\Config;

/**
 * Resolves configurable contract implementations supplied by the host
 * application.
 *
 * The package exposes contracts at the boundaries where application-specific
 * behavior is expected: principal lookup, audit emission, SCIM translation, and
 * membership reconciliation. Concentrating those bindings in a dedicated
 * reader keeps service-provider validation deterministic and prevents container
 * wiring code from duplicating raw configuration paths.
 *
 * These methods intentionally return class strings rather than resolved
 * instances. The service provider remains responsible for binding lifecycle,
 * while this reader owns only the normalization and discovery of extension
 * points.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class ContractConfiguration
{
    /**
     * Return the principal resolver class used to map inbound identities to
     * local principals.
     *
     * The service provider binds this implementation into the container before
     * any login flow runs. That keeps the package's identity-validation layer
     * decoupled from application-specific account lookup, linking, and
     * authorization policy.
     */
    public function principalResolver(): string
    {
        return Config::string('sso.contracts.principal_resolver');
    }

    /**
     * Return the audit sink class used to persist or emit security events.
     *
     * The package uses this contract for side-effectful audit trails without
     * assuming a specific storage backend or observability pipeline.
     * Implementations may write to logs, queues, external SIEM systems, or
     * durable audit tables, so this reader keeps that side-effect boundary
     * configurable instead of hard-coded.
     */
    public function auditSink(): string
    {
        return Config::string('sso.contracts.audit_sink');
    }

    /**
     * Return the SCIM user adapter responsible for translating local users into
     * SCIM resources.
     *
     * Controllers depend on this adapter when serializing application users
     * into the wire format expected by external SCIM clients. The adapter
     * exists because the package cannot assume a universal local user shape,
     * field naming convention, or attribute exposure policy.
     */
    public function scimUserAdapter(): string
    {
        return Config::string('sso.contracts.scim_user_adapter');
    }

    /**
     * Return the SCIM group adapter responsible for translating local groups
     * into SCIM resources.
     *
     * This boundary allows applications to decide what constitutes a "group"
     * and how group metadata should be exposed through the SCIM surface.
     * Resolution remains class-string based so the service provider can control
     * construction and lifecycle.
     */
    public function scimGroupAdapter(): string
    {
        return Config::string('sso.contracts.scim_group_adapter');
    }

    /**
     * Return the reconciler class that applies SCIM membership side effects.
     *
     * The reconciler handles write-side consequences of SCIM membership
     * changes, which can vary significantly between applications. Centralizing
     * that binding here makes it explicit that SCIM writes are delegated to the
     * host application's domain rules rather than encoded in package
     * controllers.
     */
    public function scimReconciler(): string
    {
        return Config::string('sso.contracts.scim_reconciler');
    }
}
