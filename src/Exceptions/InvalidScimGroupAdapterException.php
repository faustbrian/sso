<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when the configured SCIM group adapter does not satisfy the package
 * contract.
 *
 * This is a boot-time configuration exception raised while the service
 * provider resolves extension points from the Laravel container. It protects
 * the SCIM group endpoints from running with an adapter that cannot honor the
 * package's expected list, create, patch, and delete semantics.
 *
 * The exception exists so miswired application bindings fail during package
 * registration instead of surfacing later during a live provisioning request.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidScimGroupAdapterException extends ConfigurationException
{
    /**
     * Create an exception for an invalid SCIM group adapter binding.
     *
     * Used when the resolved container service does not implement the group
     * adapter interface required by the package's SCIM orchestration layer.
     *
     * @return self Exception describing the invalid group adapter
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.system.errors.invalid_scim_group_adapter'));
    }
}
