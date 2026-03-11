<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when the configured SCIM reconciler binding does not implement the
 * package contract.
 *
 * The reconciler is the top-level orchestration point for SCIM-driven identity
 * synchronization. This exception is raised during package boot when the
 * container resolves a service that cannot provide the reconciliation behavior
 * expected by commands and request handlers.
 *
 * Failing early here keeps reconciliation misconfiguration out of the request
 * path and prevents long-running sync operations from starting with an invalid
 * dependency graph.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidScimReconcilerException extends ConfigurationException
{
    /**
     * Create an exception for an invalid SCIM reconciler binding.
     *
     * Used when the resolved service does not implement the reconciler
     * contract consumed by package commands and SCIM write flows.
     *
     * @return self Exception describing the invalid reconciler service
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.system.errors.invalid_scim_reconciler'));
    }
}
